use anyhow::Result;
use clap::Parser;
use software_supply_chain_exporter::{
    config::{Cli, Config, Source},
    docker::get_docker_images,
    metrics::export_metrics,
    sbom::{clean, create_sboms},
    scan::scan,
};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    info!("Reading config");
    let config: Config = serde_yaml::from_str(&std::fs::read_to_string(cli.config)?)?;

    info!("Fetching docker images that are used in containers from docker");
    let mut sources = get_docker_images().await?;
    // sources.push(Source::HostDirectory { path: "/".into() });

    info!("Start generating SBOMs");
    let sboms = create_sboms(&config, &sources).await?;

    info!("Compare generated SBOMs against vulnerability databases");
    let scans = scan(&sboms).await?;

    info!("Format SBOM and vulnerability data as metrics");
    export_metrics(&config, sboms, scans)?;

    info!("Clean up old cache files");
    clean(&config).await?;

    Ok(())
}
