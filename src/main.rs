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

    if let Err(error) = server::run_server(state, shutdown_signal()).await {
        error!(?error, "relay server stopped with error");
        std::process::exit(1);
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
        "Ctrl-C"
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
        "SIGTERM"
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<&str>();

    let signal = tokio::select! {
        signal = ctrl_c => signal,
        signal = terminate => signal,
    };
    info!(signal, "received shutdown signal; shutting down gracefully");
}
