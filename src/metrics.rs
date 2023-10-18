use std::{collections::HashMap, fs::File, io::Write};

use anyhow::Result;
use prometheus_client::{
    encoding::{text::encode, EncodeLabelSet},
    metrics::{counter::Counter, family::Family},
    registry::Registry,
};
use serde_json::Value;

use crate::{
    config::{Config, Source},
    sbom::Sbom,
    scan::Scan,
};

pub fn export_metrics(
    config: &Config,
    sboms: HashMap<Source, Value>,
    scans: HashMap<Source, Scan>,
) -> Result<()> {
    let mut registry = <Registry>::default();
    let syft_metrics = Family::<SbomLabels, Counter>::default();
    let grype_metrics = Family::<ScanLabels, Counter>::default();

    registry.register("sbom", "", syft_metrics.clone());
    registry.register("vulnerability_scans", "", grype_metrics.clone());

    std::fs::create_dir_all(config.metrics_path().parent().unwrap())?;
    let mut output = File::create(config.metrics_path())?;

    let mut buffer = String::new();

    for (source, sbom) in sboms {
        let sbom: Sbom = serde_json::from_value(sbom)?;
        for entry in sbom.artifacts {
            let source = source.clone().into();
            syft_metrics
                .get_or_create(&SbomLabels {
                    software: entry.name,
                    version: entry.version,
                    source,
                })
                .inc();
        }
    }

    for (source, scan) in scans {
        for entry in scan.matches {
            let source = source.clone().into();
            grype_metrics
                .get_or_create(&ScanLabels {
                    source,
                    severity: entry.vulnerability.severity,
                    urls: entry.vulnerability.urls.join(", "),
                    software: entry.artifact.name,
                })
                .inc();
        }
    }

    encode(&mut buffer, &registry)?;
    output.write_all(buffer.as_bytes())?;

    Ok(())
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SbomLabels {
    pub software: String,
    pub version: String,
    #[prometheus(flatten)]
    pub source: SourceLabels,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ScanLabels {
    pub severity: String,
    pub urls: String,
    pub software: String,
    #[prometheus(flatten)]
    pub source: SourceLabels,
}

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SourceLabels {
    pub image: Option<String>,
    pub id: Option<String>,
    pub path: Option<String>,
}

impl From<Source> for SourceLabels {
    fn from(value: Source) -> Self {
        match value {
            Source::DockerImage { name, id } => Self {
                image: Some(name),
                id: Some(id),
                ..Default::default()
            },
            Source::HostDirectory { path } => Self {
                path: Some(path.to_string_lossy().to_string()),
                ..Default::default()
            },
        }
    }
}
