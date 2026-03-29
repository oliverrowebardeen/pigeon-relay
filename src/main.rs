mod apns;
mod auth;
mod config;
mod protocol;
mod queue;
mod server;
mod state;

use std::sync::Arc;

use apns::ApnsClient;
use config::Config;
use state::RelayState;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .init();

    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            error!(?error, "failed to load configuration");
            std::process::exit(1);
        }
    };

    let apns_client = if config.apns.enabled {
        match ApnsClient::new(&config.apns) {
            Ok(client) => Some(Arc::new(client)),
            Err(error) => {
                error!(?error, "failed to initialize APNS client");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    let state = Arc::new(RelayState::new(config.clone(), apns_client));

    info!(
        relay_addr = %config.relay_addr,
        apns_enabled = config.apns.enabled,
        "starting pigeon-relay"
    );

    let shutdown = async {
        tokio::signal::ctrl_c().await.ok();
        info!("received ctrl-c; shutting down gracefully");
    };

    if let Err(error) = server::run_server(state, shutdown).await {
        error!(?error, "relay server stopped with error");
        std::process::exit(1);
    }
}
