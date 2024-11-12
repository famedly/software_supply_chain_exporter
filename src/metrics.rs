use std::{collections::HashMap, fs::File, io::Write};

use anyhow::Result;
use chrono::Utc;
use prometheus_client::{
    encoding::{text::encode, EncodeLabelSet},
    metrics::{counter::Counter, family::Family},
    registry::Registry,
};
use rust_decimal::Decimal;
use serde_json::Value;

use crate::{
    config::{Config, Source},
    sbom::Sbom,
    scan::{Cvss, CvssMetrics, Scan},
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

    let cvss_fallback = Cvss {
        source: String::from(""),
        cvss_type: String::from(""),
        version: String::from(""),
        vector: String::from(""),
        metrics: CvssMetrics {
            base_score: Decimal::new(0, 1),
            exploitability_score: Decimal::new(0, 1),
            impact_score: Decimal::new(0, 1),
        },
    };

    for (source, sbom) in sboms {
        let sbom: Sbom = serde_json::from_value(sbom)?;
        for entry in sbom.packages {
            let source = source.clone().into();
            if entry.versionInfo.is_empty() {
                continue;
            };
            syft_metrics
                .get_or_create(&SbomLabels {
                    software: entry.name,
                    version: entry.versionInfo,
                    source,
                })
                .inc();
        }
    }

    for (source, scan) in scans {
        for entry in scan.matches {
            let source: SourceLabels = source.clone().into();
            let title: String = format!(
                "{} {}: {}",
                source.image.clone().unwrap_or_default(),
                entry.artifact.name,
                entry.vulnerability.id
            );
            let (cvss_base_score, cvss_exploitability_score, cvss_impact_score) =
                if !entry.vulnerability.cvss.is_empty() {
                    (
                        entry
                            .vulnerability
                            .cvss
                            .first()
                            .unwrap_or(&cvss_fallback)
                            .metrics
                            .base_score
                            .to_string(),
                        entry
                            .vulnerability
                            .cvss
                            .first()
                            .unwrap_or(&cvss_fallback)
                            .metrics
                            .exploitability_score
                            .to_string(),
                        entry
                            .vulnerability
                            .cvss
                            .first()
                            .unwrap_or(&cvss_fallback)
                            .metrics
                            .impact_score
                            .to_string(),
                    )
                } else {
                    (
                        String::from("undefined"),
                        String::from("undefined"),
                        String::from("undefined"),
                    )
                };
            grype_metrics
                .get_or_create(&ScanLabels {
                    source,
                    cvss_base_score,
                    cvss_exploitability_score,
                    cvss_impact_score,
                    title,
                    severity: entry.vulnerability.severity,
                    urls: entry.vulnerability.urls.join(", "),
                    cve: entry.vulnerability.id,
                    fixed: entry.vulnerability.fix.state.to_string(),
                    fixed_versions: entry.vulnerability.fix.versions.join(", "),
                    software: entry.artifact.name,
                    scan_date: Utc::now().date_naive().to_string(),
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
    pub cve: String,
    pub cvss_base_score: String,
    pub cvss_exploitability_score: String,
    pub cvss_impact_score: String,
    pub severity: String,
    pub urls: String,
    pub software: String,
    pub fixed: String,
    pub fixed_versions: String,
    pub scan_date: String,
    pub title: String,
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
