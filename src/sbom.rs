use std::{
    collections::HashMap,
    ffi::OsString,
    fs::File,
    path::PathBuf,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result};
use serde_json::Value;
use tokio::process::Command;
use tracing::debug;
use walkdir::WalkDir;

use crate::config::{Config, Source};

#[allow(non_snake_case)]
#[derive(Clone, Debug, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SbomEntry {
    pub name: String,
    #[serde(default)]
    pub versionInfo: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Sbom {
    pub packages: Vec<SbomEntry>,
}

/// Call syft for all running containers and create JSON SBOM.
/// Syft doesn't take multiple inputs at once, so we loop over the images.
pub async fn create_sboms(
    config: &Config,
    sources: &Vec<Source>,
) -> Result<HashMap<Source, Value>> {
    let mut sboms = HashMap::new();
    for source in sources {
        if config.generate_sboms {
            let res = create_sbom(config.clone(), source.clone()).await;
            match res {
                Err(e) => println!("Error creating sbom: {e:?}"),
                Ok((source, sbom)) => {
                    sboms.insert(source, sbom);
                }
            }
        } else if let (Source::DockerImage { ref name, id: _ }, Some(sbom_path)) =
            (source, config.sbom_path(source))
        {
            let res = get_sbom(name.into(), sbom_path).await;
            match res {
                Err(e) => println!("Error loading sbom: {e:?}"),
                Ok(sbom) => {
                    sboms.insert(source.clone(), sbom);
                }
            }
        }
    }

    Ok(sboms)
}

#[tracing::instrument(skip(sbom_path))]
async fn get_sbom(scan_target: OsString, sbom_path: PathBuf) -> Result<Value> {
    if std::fs::metadata(&sbom_path).is_ok() {
        debug!("found cached sbom, reading and parsing it now");
        let sbom_file = File::open(&sbom_path)?;
        let parsed_sbom = serde_json::from_reader(sbom_file)?;
        Ok(parsed_sbom)
    } else {
        debug!("Trying to get sbom from image attestations");
        let mut command = Command::new("docker");
        let arch = match std::env::consts::ARCH {
            "x86_64" => "linux/amd64",
            "aarch64" => "linux/arm64",
            _ => "",
        };

        command
            .arg("buildx")
            .arg("imagetools")
            .arg("inspect")
            .arg(scan_target)
            .arg("--format")
            .arg("{{ json .SBOM }}");

        let output = command.output().await?;
        let output: Value = serde_json::from_slice(&output.stdout)?;

        let parsed_output = match output.get(arch) {
            Some(v) => v.get("SPDX"),
            None => output.get("SPDX"),
        }
        .context("Image does not have compatible sbom attestation")?;

        Ok(parsed_output.to_owned())
    }
}

#[tracing::instrument(skip(config))]
async fn create_sbom(config: Config, source: Source) -> Result<(Source, Value)> {
    let source = source.clone();
    let (scan_target, sbom_path): (OsString, Option<PathBuf>) = match source {
        Source::DockerImage { ref name, id: _ } => (name.into(), config.sbom_path(&source)),
        Source::HostDirectory { ref path } => (path.into(), config.sbom_path(&source)),
    };

    if let Some(sbom_path) = sbom_path.clone() {
        debug!("sbom is cacheable, checking for cached result");
        if let Ok(parsed_cache) = get_sbom(scan_target.clone(), sbom_path).await {
            return Ok((source, parsed_cache));
        }
    }

    debug!("not using cached sbom, preparing to run syft against source");
    let mut command = Command::new("syft");
    command
        .arg("scan")
        .arg("--quiet") // Supress non-error output
        .arg("-o")
        .arg("spdx-json")
        .arg("--override-default-catalogers")
        .arg("all")
        .env("SYFT_PARALLELISM", "1");

    if matches!(source, Source::HostDirectory { .. }) {
        debug!("we're running against a host directory, append excludes from the config file");
        for exclude in config.excludes {
            let mut relative_exclude = OsString::from(".");
            relative_exclude.push(exclude);
            command.arg("--exclude").arg(relative_exclude);
        }
    }

    debug!("running syft now");
    let output = command.arg(scan_target).output().await?;

    if let Some(sbom_path) = sbom_path {
        debug!("sbom is cacheable, writing it to cache location");
        std::fs::create_dir_all(sbom_path.parent().unwrap())?;
        std::fs::write(sbom_path, &output.stdout)?;
    }

    debug!("parsing sbom for further processing");
    let parsed_output = serde_json::from_slice(&output.stdout)?;
    Ok((source, parsed_output))
}

pub async fn clean(config: &Config) -> Result<()> {
    let now = SystemTime::now();

    let old_files = WalkDir::new(&config.base_path)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter_map(|e| Some((e.path().to_owned(), e.metadata().ok()?)))
        .filter(|(_, metadata)| metadata.is_file())
        .filter(|(path, _)| {
            path.extension()
                .filter(|ext| ext.eq(&OsString::from("json")))
                .is_some()
        })
        .filter(|(_, metadata)| {
            // Filter files based on their last access time.
            if let Ok(accessed_time) = metadata.accessed() {
                now.duration_since(accessed_time)
                    .unwrap_or(Duration::from_secs(0))
                    >= config.cache_duration
            } else {
                // Handle cases where access time cannot be determined.
                false
            }
        })
        .map(|(path, _)| path);
    for path in old_files {
        std::fs::remove_file(path)?;
    }
    Ok(())
}
