use std::env;
use std::time::Duration;

use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Config {
    pub relay_addr: String,
    pub message_ttl: Duration,
    pub max_message_bytes: usize,
    pub max_queue_per_recipient: usize,
    pub challenge_ttl: Duration,
    pub session_ttl: Duration,
    pub rate_limit_per_min: u32,
    pub ping_interval: Duration,
    pub pong_timeout: Duration,
    pub apns: ApnsConfig,
}

#[derive(Debug, Clone)]
pub struct ApnsConfig {
    pub enabled: bool,
    pub team_id: Option<String>,
    pub key_id: Option<String>,
    pub private_key_path: Option<String>,
    pub topic: Option<String>,
    pub environment: ApnsEnvironment,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum ApnsEnvironment {
    #[default]
    Sandbox,
    Production,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid duration for {name}: {value}")]
    InvalidDuration { name: &'static str, value: String },
    #[error("invalid integer for {name}: {value}")]
    InvalidInteger { name: &'static str, value: String },
    #[error("APNS is enabled but missing environment variable: {0}")]
    MissingApnsField(&'static str),
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let relay_addr = env_var_or_default("RELAY_ADDR", "0.0.0.0:8080");
        let message_ttl = parse_duration("RELAY_MESSAGE_TTL", "168h")?;
        let max_message_bytes = parse_usize("RELAY_MAX_MESSAGE_BYTES", "65536")?;
        let max_queue_per_recipient = parse_usize("RELAY_MAX_QUEUE_PER_RECIPIENT", "500")?;
        let challenge_ttl = parse_duration("RELAY_CHALLENGE_TTL", "30s")?;
        let session_ttl = parse_duration("RELAY_SESSION_TTL", "24h")?;
        let rate_limit_per_min = parse_u32("RELAY_RATE_LIMIT_PER_MIN", "60")?;
        let ping_interval = parse_duration("RELAY_PING_INTERVAL", "25s")?;
        let pong_timeout = parse_duration("RELAY_PONG_TIMEOUT", "60s")?;

        let apns_enabled = parse_bool("APNS_ENABLED", false);
        let apns_environment = parse_apns_environment(env::var("APNS_ENV").ok());

        let apns = ApnsConfig {
            enabled: apns_enabled,
            team_id: env::var("APNS_TEAM_ID").ok(),
            key_id: env::var("APNS_KEY_ID").ok(),
            private_key_path: env::var("APNS_PRIVATE_KEY_PATH").ok(),
            topic: env::var("APNS_TOPIC").ok(),
            environment: apns_environment,
        };

        if apns.enabled {
            if apns.team_id.is_none() {
                return Err(ConfigError::MissingApnsField("APNS_TEAM_ID"));
            }
            if apns.key_id.is_none() {
                return Err(ConfigError::MissingApnsField("APNS_KEY_ID"));
            }
            if apns.private_key_path.is_none() {
                return Err(ConfigError::MissingApnsField("APNS_PRIVATE_KEY_PATH"));
            }
            if apns.topic.is_none() {
                return Err(ConfigError::MissingApnsField("APNS_TOPIC"));
            }
        }

        Ok(Self {
            relay_addr,
            message_ttl,
            max_message_bytes,
            max_queue_per_recipient,
            challenge_ttl,
            session_ttl,
            rate_limit_per_min,
            ping_interval,
            pong_timeout,
            apns,
        })
    }
}

fn env_var_or_default(name: &'static str, default: &'static str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn parse_duration(name: &'static str, default: &'static str) -> Result<Duration, ConfigError> {
    let value = env_var_or_default(name, default);
    humantime::parse_duration(&value).map_err(|_| ConfigError::InvalidDuration { name, value })
}

fn parse_usize(name: &'static str, default: &'static str) -> Result<usize, ConfigError> {
    let value = env_var_or_default(name, default);
    value
        .parse::<usize>()
        .map_err(|_| ConfigError::InvalidInteger { name, value })
}

fn parse_u32(name: &'static str, default: &'static str) -> Result<u32, ConfigError> {
    let value = env_var_or_default(name, default);
    value
        .parse::<u32>()
        .map_err(|_| ConfigError::InvalidInteger { name, value })
}

fn parse_bool(name: &'static str, default: bool) -> bool {
    match env::var(name) {
        Ok(value) => matches!(value.to_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => default,
    }
}

fn parse_apns_environment(value: Option<String>) -> ApnsEnvironment {
    match value.as_deref().map(|v| v.to_ascii_lowercase()).as_deref() {
        Some("production") => ApnsEnvironment::Production,
        _ => ApnsEnvironment::Sandbox,
    }
}
