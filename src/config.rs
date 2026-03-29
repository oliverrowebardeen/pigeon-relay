use std::env;
use std::str::FromStr;
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
    pub max_concurrent_challenges: usize,
    pub max_push_registrations: usize,
    pub push_token_ttl: Duration,
    pub apns: ApnsConfig,
}

#[derive(Debug, Clone)]
pub struct ApnsConfig {
    pub enabled: bool,
    pub team_id: Option<String>,
    pub key_id: Option<String>,
    pub private_key_path: Option<String>,
    pub sandbox_key_id: Option<String>,
    pub sandbox_private_key_path: Option<String>,
    pub production_key_id: Option<String>,
    pub production_private_key_path: Option<String>,
    pub topic: Option<String>,
    pub environment: ApnsEnvironment,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum ApnsEnvironment {
    #[default]
    Sandbox,
    Production,
}

impl FromStr for ApnsEnvironment {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "production" => Ok(Self::Production),
            "sandbox" => Ok(Self::Sandbox),
            _ => Err(()),
        }
    }
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
        let max_message_bytes = parse_num("RELAY_MAX_MESSAGE_BYTES", "65536")?;
        let max_queue_per_recipient = parse_num("RELAY_MAX_QUEUE_PER_RECIPIENT", "500")?;
        let challenge_ttl = parse_duration("RELAY_CHALLENGE_TTL", "30s")?;
        let session_ttl = parse_duration("RELAY_SESSION_TTL", "24h")?;
        let rate_limit_per_min = parse_num("RELAY_RATE_LIMIT_PER_MIN", "60")?;
        let ping_interval = parse_duration("RELAY_PING_INTERVAL", "25s")?;
        let pong_timeout = parse_duration("RELAY_PONG_TIMEOUT", "60s")?;
        let max_concurrent_challenges = parse_num("RELAY_MAX_CHALLENGES", "10000")?;
        let max_push_registrations = parse_num("RELAY_MAX_PUSH_REGISTRATIONS", "100000")?;
        let push_token_ttl = parse_duration("RELAY_PUSH_TOKEN_TTL", "720h")?;

        let apns_enabled = parse_bool("APNS_ENABLED", false);
        let apns_environment = parse_apns_environment(env::var("APNS_ENV").ok());

        let apns = ApnsConfig {
            enabled: apns_enabled,
            team_id: env::var("APNS_TEAM_ID").ok(),
            key_id: env::var("APNS_KEY_ID").ok(),
            private_key_path: env::var("APNS_PRIVATE_KEY_PATH").ok(),
            sandbox_key_id: env::var("APNS_SANDBOX_KEY_ID").ok(),
            sandbox_private_key_path: env::var("APNS_SANDBOX_PRIVATE_KEY_PATH").ok(),
            production_key_id: env::var("APNS_PRODUCTION_KEY_ID").ok(),
            production_private_key_path: env::var("APNS_PRODUCTION_PRIVATE_KEY_PATH").ok(),
            topic: env::var("APNS_TOPIC").ok(),
            environment: apns_environment,
        };

        if apns.enabled {
            if apns.team_id.is_none() {
                return Err(ConfigError::MissingApnsField("APNS_TEAM_ID"));
            }
            if apns.topic.is_none() {
                return Err(ConfigError::MissingApnsField("APNS_TOPIC"));
            }
            validate_apns_credential_pair(
                apns.key_id.as_deref(),
                apns.private_key_path.as_deref(),
                "APNS_KEY_ID",
                "APNS_PRIVATE_KEY_PATH",
            )?;
            validate_apns_credential_pair(
                apns.sandbox_key_id.as_deref(),
                apns.sandbox_private_key_path.as_deref(),
                "APNS_SANDBOX_KEY_ID",
                "APNS_SANDBOX_PRIVATE_KEY_PATH",
            )?;
            validate_apns_credential_pair(
                apns.production_key_id.as_deref(),
                apns.production_private_key_path.as_deref(),
                "APNS_PRODUCTION_KEY_ID",
                "APNS_PRODUCTION_PRIVATE_KEY_PATH",
            )?;

            let has_generic_credentials = apns.key_id.is_some() && apns.private_key_path.is_some();
            let has_sandbox_credentials = has_generic_credentials
                || (apns.sandbox_key_id.is_some() && apns.sandbox_private_key_path.is_some());
            let has_production_credentials = has_generic_credentials
                || (apns.production_key_id.is_some() && apns.production_private_key_path.is_some());

            if !has_sandbox_credentials {
                return Err(ConfigError::MissingApnsField(
                    "APNS_SANDBOX_KEY_ID or APNS_KEY_ID",
                ));
            }
            if !has_production_credentials {
                return Err(ConfigError::MissingApnsField(
                    "APNS_PRODUCTION_KEY_ID or APNS_KEY_ID",
                ));
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
            max_concurrent_challenges,
            max_push_registrations,
            push_token_ttl,
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

fn parse_num<T: FromStr>(name: &'static str, default: &'static str) -> Result<T, ConfigError> {
    let value = env_var_or_default(name, default);
    value
        .parse::<T>()
        .map_err(|_| ConfigError::InvalidInteger { name, value })
}

fn parse_bool(name: &'static str, default: bool) -> bool {
    match env::var(name) {
        Ok(value) => matches!(value.to_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => default,
    }
}

fn parse_apns_environment(value: Option<String>) -> ApnsEnvironment {
    value.and_then(|v| v.parse().ok()).unwrap_or_default()
}

fn validate_apns_credential_pair(
    key_id: Option<&str>,
    private_key_path: Option<&str>,
    key_id_field: &'static str,
    private_key_path_field: &'static str,
) -> Result<(), ConfigError> {
    match (key_id, private_key_path) {
        (Some(_), None) => Err(ConfigError::MissingApnsField(private_key_path_field)),
        (None, Some(_)) => Err(ConfigError::MissingApnsField(key_id_field)),
        _ => Ok(()),
    }
}
