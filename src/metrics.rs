use crate::ImageInfo;

use super::PATH;
use prometheus_client::encoding::text::encode;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use std::error::Error;
use std::fs::File;
use std::io::Write;

pub fn export_metrics(images: &Vec<ImageInfo>) -> Result<(), Box<dyn Error>> {
    let mut registry = <Registry>::default();
    let syft_metrics = Family::<SbomLabels, Counter>::default();
    let grype_metrics = Family::<ScanLabels, Counter>::default();

    registry.register("sbom", "", syft_metrics.clone());
    registry.register("vulnerability_scans", "", grype_metrics.clone());

    let mut output = File::create(format!("{}/metrics/metrics.prom", PATH))?;
    let mut buffer = String::new();

    for image in images {
        let image_name = image.name.clone();
        let image_id = image.id.clone();
        let sbom_path = format!("{}/sbom/{}.json", PATH, image_id);
        let scan_path = format!("{}/vulns/{}.json", PATH, image_id);

        let sbom: crate::sbom::Sbom = serde_json::from_reader(File::open(sbom_path)?)?;
        let scan: crate::scan::Scan = serde_json::from_reader(File::open(scan_path)?)?;

        for entry in sbom.artifacts {
            syft_metrics
                .get_or_create(&SbomLabels {
                    software: entry.name,
                    version: entry.version,
                })
                .inc();
        }

        for entry in scan.matches {
            grype_metrics
                .get_or_create(&ScanLabels {
                    image: image_name.clone(),
                    id: entry.vulnerability.id,
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

#[derive(
    Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet, serde::Serialize, serde::Deserialize,
)]
pub struct SbomLabels {
    pub software: String,
    pub version: String,
}

#[derive(
    Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet, serde::Serialize, serde::Deserialize,
)]
pub struct ScanLabels {
    pub image: String,
    pub id: String,
    pub severity: String,
    pub urls: String,
    pub software: String,
}
