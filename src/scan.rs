use std::{collections::HashMap, process::Stdio};

use anyhow::Result;
use serde_json::Value;
use tokio::{io::AsyncWriteExt, process::Command};
use tracing::debug;

use crate::config::Source;

/// Call grype to scan SBOMs for vulnerabilities and output JSON report.
/// Just as with syft, grype doesn't take multiple inputs at once, so once again we loop.
pub async fn scan(sboms: &HashMap<Source, Value>) -> Result<HashMap<Source, Scan>> {
    let mut scans = HashMap::new();
    Command::new("grype")
        .arg("db")
        .arg("update")
        .arg("--quiet")
        .spawn()?.wait().await?;

    for (source, sbom) in sboms {
        let res = scan_single(source.clone(), sbom.clone()).await;

        match res {
            Err(e) => {
                println!("Failed to scan an sbom: {e}")
            }
            Ok((source, scan)) => {
                scans.insert(source, scan);
            }
        }
    }

    Ok(scans)
}

#[tracing::instrument(skip(sbom))]
async fn scan_single(source: Source, sbom: Value) -> Result<(Source, Scan)> {
    debug!("running grype to compare sbom against vulnerability databases");
    let mut child = Command::new("grype")
        .arg("--quiet") // Supress non-error output
        .arg("-o")
        .arg("json")
        .env("GRYPE_DB_AUTO_UPDATE", "false")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    // Code block, because we need to ensure stdin is dropped before we try
    // waiting for the child.
    {
        debug!("feed sbom into grype");
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(&serde_json::to_vec(&sbom)?).await?;
    }

    debug!("wait for grype to finish");
    let output = child.wait_with_output().await?;

    debug!("decode vulnerability report");
    let parsed_output = serde_json::from_slice(&output.stdout)?;
    Ok((source, parsed_output))
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Scan {
    pub matches: Vec<ScanEntry>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScanEntry {
    pub vulnerability: Vulnerability,
    pub artifact: ScanArtifact,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub severity: String,
    pub urls: Vec<String>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScanArtifact {
    pub name: String,
}
