use std::collections::HashMap;

use anyhow::Result;
use bollard::{container::ListContainersOptions, Docker};
use itertools::Itertools;

use crate::config::Source;

pub async fn get_docker_images() -> Result<Vec<Source>> {
    let docker = Docker::connect_with_socket_defaults()?;

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
        .unique()
        .collect())
}
