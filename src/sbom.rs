use super::ImageInfo;
use super::PATH;
use std::error::Error;
use tokio::process::Command;
use tokio::task::JoinSet;

#[derive(Clone, Debug, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SbomEntry {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Sbom {
    pub artifacts: Vec<SbomEntry>,
}

/// Call syft for all running containers and create JSON SBOM.
/// Syft doesn't take multiple inputs at once, so we loop over the images.
pub async fn create_sbom(images: &Vec<ImageInfo>) -> Result<(), Box<dyn Error>> {
    let mut set = JoinSet::new();
    for image in images {
        let image_name = image.name.clone();
        let image_id = image.id.clone();
        if std::fs::metadata(format!("{}/sbom/{}.json", PATH, image_id)).is_ok() {
            continue;
        };
        set.spawn(async move {
            let command = Command::new("syft")
                .arg("--quiet") // Supress non-error output
                .arg("-o")
                .arg("json")
                .arg("--file")
                .arg(format!("{}/sbom/{}.json", PATH, image_id))
                .arg(image_name)
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
