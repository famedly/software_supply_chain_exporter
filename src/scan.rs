use tokio::task::JoinSet;

use crate::ImageInfo;

use super::PATH;
use std::error::Error;
use tokio::process::Command;

/// Call grype to scan SBOMs for vulnerabilities and output JSON report.
/// Just as with syft, grype doesn't take multiple inputs at once, so once again we loop.
pub async fn scan(images: &Vec<ImageInfo>) -> Result<(), Box<dyn Error>> {
    let mut set = JoinSet::new();
    for image in images {
        let image_id = image.id.clone();
        set.spawn(async move {
            let command = Command::new("grype")
                .arg("--quiet") // Supress non-error output
                .arg("-o")
                .arg("json")
                .arg("--file")
                .arg(format!("{}/vulns/{}.json", PATH, image_id))
                .arg(format!("{}/sbom/{}.json", PATH, image_id))
                .spawn();

            match command {
                Ok(mut child) => Ok(child.wait().await),
                Err(e) => Err(e),
            }
        });
    }

    while let Some(res) = set.join_next().await {
        match res {
            Err(e) => println!("Error joining tasks: {e}"),
            Ok(Err(e)) => println!("Error spawning child process: {e}"),
            _ => {}
        }
    }

    Ok(())
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
