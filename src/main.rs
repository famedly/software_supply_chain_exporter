const PATH: &str = "/opt/syft_grype"; // TODO: Take path as command line argument
use bollard::container::ListContainersOptions;
use bollard::service::ContainerSummary;
use std::collections::HashMap;
use std::default::Default;
use std::error::Error;

mod metrics;
mod sbom;
mod scan;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("Getting images from docker");
    let images = get_docker_images().await?;

    // TODO: Cache a simple mapping of image name to id/hash, and only pass changed images on to
    // syft.
    println!("Creating SBOM");
    sbom::create_sbom(&images).await?;
    println!("Scanning containers for vulnerabilities");
    scan::scan(&images).await?;

    // TODO: also scan native packages
    println!("Generating metrics");
    metrics::export_metrics(&images)?;

    Ok(())
}

async fn get_docker_images() -> Result<Vec<ImageInfo>, Box<dyn Error>> {
    let docker = bollard::Docker::connect_with_socket_defaults()?;

    let filters: HashMap<String, Vec<String>> = HashMap::new();

    let options = Some(ListContainersOptions {
        all: true,
        filters,
        ..Default::default()
    });

    Ok(docker
        .list_containers(options)
        .await?
        .iter()
        .map(|v| (*v).clone().into())
        .collect())
}

/// This stores the only parts of the docker container output that we need to be able to call syft
/// and keep track of changes in used images.
#[derive(Default, Debug, Clone)]
pub struct ImageInfo {
    pub name: String,
    pub id: String,
}

impl From<ContainerSummary> for ImageInfo {
    fn from(value: ContainerSummary) -> Self {
        Self {
            name: value.image.unwrap_or_default(),
            id: value.image_id.unwrap_or_default(),
        }
    }
}
