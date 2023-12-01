use std::{fmt::Display, path::PathBuf, time::Duration};

use bollard::service::ContainerSummary;
use clap::Parser;
use serde::Deserialize;

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    pub base_path: PathBuf,
    pub metrics_path: Option<PathBuf>,
    #[serde(with = "humantime_serde")]
    pub cache_duration: Duration,
    pub excludes: Vec<PathBuf>,
    pub generate_sboms: bool,
}

impl Config {
    pub fn sbom_path(&self, source: &Source) -> Option<PathBuf> {
        match source {
            Source::DockerImage { name: _, id } => {
                Some(self.base_path.join(format!("sbom/docker/{id}.json")))
            }
            Source::HostDirectory { path: _ } => None,
        }
    }
    pub fn metrics_path(&self) -> PathBuf {
        if let Some(metrics_path) = self.metrics_path.as_deref() {
            metrics_path.into()
        } else {
            self.base_path.join("metrics/metrics.prom")
        }
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about)]
/// ssce is a software supply chain exporter. It scans the host file system and docker containers
/// running for software components from a variety of ecosystems, collects that data into a
/// software bill of materials and compares those against databases of known vulnerabilities. The
/// data generated in this way is exposed as metrics collectable by a prometheus node_exporter
/// using the textfile collector.
pub struct Cli {
    /// Path to the config file
    #[arg(short, long, default_value = "config.yaml")]
    pub config: PathBuf,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum Source {
    DockerImage { name: String, id: String },
    HostDirectory { path: PathBuf },
}

impl From<ContainerSummary> for Source {
    fn from(value: ContainerSummary) -> Self {
        Self::DockerImage {
            name: value.image.unwrap_or_default(),
            id: value.image_id.unwrap_or_default(),
        }
    }
}

impl Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::DockerImage { name, id } => write!(f, "OCI image {name} ({id})"),
            Source::HostDirectory { path } => {
                write!(f, "Host directory {}", path.to_string_lossy())
            }
        }
    }
}
