use std::collections::HashMap;

use anyhow::Result;
use bollard::{query_parameters::ListContainersOptions, Docker};
use itertools::Itertools;

use crate::config::Source;

pub async fn get_docker_images() -> Result<Vec<Source>> {
    let docker = Docker::connect_with_socket_defaults()?;

    let filters: Option<HashMap<String, Vec<String>>> = Some(HashMap::new());

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
