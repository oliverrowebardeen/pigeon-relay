use std::collections::HashSet;
use std::env;
use std::str::FromStr;
use std::time::Duration;

use chrono::Duration as ChronoDuration;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Config {
    pub relay_addr: String,
    pub max_connections: usize,
    pub message_ttl: Duration,
    pub max_message_bytes: usize,
    pub max_queue_per_recipient: usize,
    pub max_session_send_queue: usize,
    pub challenge_ttl: Duration,
    pub session_ttl: Duration,
    pub rate_limit_per_min: u32,
    pub ping_interval: Duration,
    pub pong_timeout: Duration,
    pub max_concurrent_challenges: usize,
    pub max_push_registrations: usize,
    pub push_token_ttl: Duration,
    pub allow_legacy_send: bool,
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
    pub allowed_topics: HashSet<String>,
    pub environment: ApnsEnvironment,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ApnsEnvironment {
    #[default]
    Sandbox,
    Production,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("invalid APNS environment: {value} (expected sandbox or production)")]
pub struct ApnsEnvironmentParseError {
    value: String,
}

impl FromStr for ApnsEnvironment {
    type Err = ApnsEnvironmentParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "production" => Ok(Self::Production),
            "sandbox" => Ok(Self::Sandbox),
            _ => Err(ApnsEnvironmentParseError {
                value: s.to_string(),
            }),
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid duration for {name}: {value}")]
    InvalidDuration { name: &'static str, value: String },
    #[error("invalid duration for {name}: {value} (must be greater than zero)")]
    ZeroDuration { name: &'static str, value: String },
    #[error("invalid duration for {name}: {value} (must be at most 365d)")]
    DurationOutOfRange { name: &'static str, value: String },
    #[error(
        "invalid duration for {name}: {value} (must be greater than or equal to {other_name}={other_value})"
    )]
    DurationTooShort {
        name: &'static str,
        value: String,
        other_name: &'static str,
        other_value: String,
    },
    #[error("invalid integer for {name}: {value}")]
    InvalidInteger { name: &'static str, value: String },
    #[error("invalid integer for {name}: {value} (maximum is {max})")]
    IntegerOutOfRange {
        name: &'static str,
        value: String,
        max: usize,
    },
    #[error("invalid integer for {name}: {value} (must be greater than zero)")]
    ZeroInteger { name: &'static str, value: String },
    #[error(
        "invalid boolean for {name}: {value} (expected one of: 1, 0, true, false, yes, no, on, off)"
    )]
    InvalidBoolean { name: &'static str, value: String },
    #[error("{0}")]
    InvalidApnsEnvironment(#[from] ApnsEnvironmentParseError),
    #[error("APNS is enabled but missing environment variable: {0}")]
    MissingApnsField(&'static str),
}

const MAX_CONFIG_DURATION: Duration = Duration::from_secs(365 * 24 * 60 * 60);

#[derive(Debug)]
struct ParsedValue<T> {
    name: &'static str,
    raw: String,
    value: T,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_env_with(|name| env::var(name).ok())
    }

    fn from_env_with<F>(get_var: F) -> Result<Self, ConfigError>
    where
        F: Fn(&'static str) -> Option<String>,
    {
        let relay_addr = env_var_or_default(&get_var, "RELAY_ADDR", "0.0.0.0:8080");
        let max_connections = parse_num(&get_var, "RELAY_MAX_CONNECTIONS", "1024")?;
        require_non_zero(&max_connections)?;
        if max_connections.value > 65_536 {
            return Err(ConfigError::IntegerOutOfRange {
                name: max_connections.name,
                value: max_connections.raw,
                max: 65_536,
            });
        }
        let message_ttl = parse_duration(&get_var, "RELAY_MESSAGE_TTL", "168h")?;
        let max_message_bytes = parse_num(&get_var, "RELAY_MAX_MESSAGE_BYTES", "65536")?;
        let max_queue_per_recipient = parse_num(&get_var, "RELAY_MAX_QUEUE_PER_RECIPIENT", "500")?;
        let max_session_send_queue = parse_num(&get_var, "RELAY_MAX_SESSION_SEND_QUEUE", "128")?;
        let challenge_ttl = parse_duration(&get_var, "RELAY_CHALLENGE_TTL", "30s")?;
        let session_ttl = parse_duration(&get_var, "RELAY_SESSION_TTL", "24h")?;
        let rate_limit_per_min = parse_num(&get_var, "RELAY_RATE_LIMIT_PER_MIN", "60")?;
        let ping_interval = parse_duration(&get_var, "RELAY_PING_INTERVAL", "25s")?;
        let pong_timeout = parse_duration(&get_var, "RELAY_PONG_TIMEOUT", "60s")?;
        let max_concurrent_challenges = parse_num(&get_var, "RELAY_MAX_CHALLENGES", "10000")?;
        let max_push_registrations = parse_num(&get_var, "RELAY_MAX_PUSH_REGISTRATIONS", "100000")?;
        let push_token_ttl = parse_duration(&get_var, "RELAY_PUSH_TOKEN_TTL", "720h")?;
        let allow_legacy_send = parse_bool(&get_var, "RELAY_ALLOW_LEGACY_SEND", false)?;

        let apns_enabled = parse_bool(&get_var, "APNS_ENABLED", false)?;
        let apns_environment = parse_apns_environment(get_var("APNS_ENV"))?;

        require_non_zero(&max_message_bytes)?;
        require_non_zero(&max_queue_per_recipient)?;
        require_non_zero(&max_session_send_queue)?;
        require_non_zero(&rate_limit_per_min)?;
        require_non_zero(&max_concurrent_challenges)?;
        require_non_zero(&max_push_registrations)?;
        require_non_zero_duration(&ping_interval)?;
        require_non_zero_duration(&pong_timeout)?;

        if pong_timeout.value < ping_interval.value {
            return Err(ConfigError::DurationTooShort {
                name: pong_timeout.name,
                value: pong_timeout.raw.clone(),
                other_name: ping_interval.name,
                other_value: ping_interval.raw.clone(),
            });
        }

        let apns_topic = get_var("APNS_TOPIC")
            .map(|topic| topic.trim().to_string())
            .filter(|topic| !topic.is_empty());
        let mut allowed_topics: HashSet<String> = get_var("APNS_ALLOWED_TOPICS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|topic| !topic.is_empty())
            .map(str::to_string)
            .collect();
        allowed_topics.extend(apns_topic.iter().cloned());

        let apns = ApnsConfig {
            enabled: apns_enabled,
            team_id: get_var("APNS_TEAM_ID"),
            key_id: get_var("APNS_KEY_ID"),
            private_key_path: get_var("APNS_PRIVATE_KEY_PATH"),
            sandbox_key_id: get_var("APNS_SANDBOX_KEY_ID"),
            sandbox_private_key_path: get_var("APNS_SANDBOX_PRIVATE_KEY_PATH"),
            production_key_id: get_var("APNS_PRODUCTION_KEY_ID"),
            production_private_key_path: get_var("APNS_PRODUCTION_PRIVATE_KEY_PATH"),
            topic: apns_topic,
            allowed_topics,
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
            max_connections: max_connections.value,
            message_ttl: message_ttl.value,
            max_message_bytes: max_message_bytes.value,
            max_queue_per_recipient: max_queue_per_recipient.value,
            max_session_send_queue: max_session_send_queue.value,
            challenge_ttl: challenge_ttl.value,
            session_ttl: session_ttl.value,
            rate_limit_per_min: rate_limit_per_min.value,
            ping_interval: ping_interval.value,
            pong_timeout: pong_timeout.value,
            max_concurrent_challenges: max_concurrent_challenges.value,
            max_push_registrations: max_push_registrations.value,
            push_token_ttl: push_token_ttl.value,
            allow_legacy_send,
            apns,
        })
    }
}

fn env_var_or_default<F>(get_var: &F, name: &'static str, default: &'static str) -> String
where
    F: Fn(&'static str) -> Option<String>,
{
    get_var(name).unwrap_or_else(|| default.to_string())
}

fn parse_duration<F>(
    get_var: &F,
    name: &'static str,
    default: &'static str,
) -> Result<ParsedValue<Duration>, ConfigError>
where
    F: Fn(&'static str) -> Option<String>,
{
    let raw = env_var_or_default(get_var, name, default);
    let value = humantime::parse_duration(&raw).map_err(|_| ConfigError::InvalidDuration {
        name,
        value: raw.clone(),
    })?;
    validate_duration_range(name, &raw, value)?;
    Ok(ParsedValue { name, raw, value })
}

fn parse_num<F, T: FromStr>(
    get_var: &F,
    name: &'static str,
    default: &'static str,
) -> Result<ParsedValue<T>, ConfigError>
where
    F: Fn(&'static str) -> Option<String>,
{
    let raw = env_var_or_default(get_var, name, default);
    let value = raw.parse::<T>().map_err(|_| ConfigError::InvalidInteger {
        name,
        value: raw.clone(),
    })?;
    Ok(ParsedValue { name, raw, value })
}

fn parse_bool<F>(get_var: &F, name: &'static str, default: bool) -> Result<bool, ConfigError>
where
    F: Fn(&'static str) -> Option<String>,
{
    match get_var(name) {
        Some(value) => match value.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => Err(ConfigError::InvalidBoolean { name, value }),
        },
        None => Ok(default),
    }
}

fn parse_apns_environment(value: Option<String>) -> Result<ApnsEnvironment, ConfigError> {
    value.map_or(Ok(ApnsEnvironment::default()), |value| {
        value.parse().map_err(Into::into)
    })
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

fn validate_duration_range(
    name: &'static str,
    raw: &str,
    value: Duration,
) -> Result<(), ConfigError> {
    if value > MAX_CONFIG_DURATION || ChronoDuration::from_std(value).is_err() {
        return Err(ConfigError::DurationOutOfRange {
            name,
            value: raw.to_string(),
        });
    }

    Ok(())
}

fn require_non_zero<T>(parsed: &ParsedValue<T>) -> Result<(), ConfigError>
where
    T: Default + PartialEq,
{
    if parsed.value == T::default() {
        return Err(ConfigError::ZeroInteger {
            name: parsed.name,
            value: parsed.raw.clone(),
        });
    }

    Ok(())
}

fn require_non_zero_duration(parsed: &ParsedValue<Duration>) -> Result<(), ConfigError> {
    if parsed.value.is_zero() {
        return Err(ConfigError::ZeroDuration {
            name: parsed.name,
            value: parsed.raw.clone(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn config_from(vars: &[(&'static str, &'static str)]) -> Result<Config, ConfigError> {
        let vars: HashMap<&'static str, String> = vars
            .iter()
            .map(|(name, value)| (*name, (*value).to_string()))
            .collect();

        Config::from_env_with(|name| vars.get(name).cloned())
    }

    #[test]
    fn zero_ping_interval_rejected() {
        let err = config_from(&[("RELAY_PING_INTERVAL", "0s")])
            .expect_err("zero ping interval should fail");
        assert!(matches!(
            err,
            ConfigError::ZeroDuration {
                name: "RELAY_PING_INTERVAL",
                ..
            }
        ));
    }

    #[test]
    fn pong_timeout_less_than_ping_interval_rejected() {
        let err = config_from(&[
            ("RELAY_PING_INTERVAL", "60s"),
            ("RELAY_PONG_TIMEOUT", "30s"),
        ])
        .expect_err("pong timeout shorter than ping should fail");
        assert!(matches!(
            err,
            ConfigError::DurationTooShort {
                name: "RELAY_PONG_TIMEOUT",
                other_name: "RELAY_PING_INTERVAL",
                ..
            }
        ));
    }

    #[test]
    fn connection_limit_validated() {
        assert_eq!(config_from(&[]).unwrap().max_connections, 1024);
        assert_eq!(
            config_from(&[("RELAY_MAX_CONNECTIONS", "2")])
                .unwrap()
                .max_connections,
            2
        );
        for value in ["0", "65537", "-1", "invalid"] {
            assert!(config_from(&[("RELAY_MAX_CONNECTIONS", value)]).is_err());
        }
    }

    #[test]
    fn zero_session_send_queue_rejected() {
        let err = config_from(&[("RELAY_MAX_SESSION_SEND_QUEUE", "0")])
            .expect_err("zero session queue should fail");
        assert!(matches!(
            err,
            ConfigError::ZeroInteger {
                name: "RELAY_MAX_SESSION_SEND_QUEUE",
                ..
            }
        ));
    }

    #[test]
    fn unknown_bool_rejected() {
        let err = config_from(&[("RELAY_ALLOW_LEGACY_SEND", "sometimes")])
            .expect_err("unknown bool should fail");
        assert!(matches!(
            err,
            ConfigError::InvalidBoolean {
                name: "RELAY_ALLOW_LEGACY_SEND",
                ..
            }
        ));
    }

    #[test]
    fn unknown_apns_environment_rejected() {
        let err =
            config_from(&[("APNS_ENV", "staging")]).expect_err("unknown apns env should fail");
        assert!(matches!(err, ConfigError::InvalidApnsEnvironment(_)));
    }

    #[test]
    fn apns_topics_include_default_and_trimmed_nonempty_extras() {
        let config = config_from(&[
            ("APNS_TOPIC", "com.example.pigeon"),
            (
                "APNS_ALLOWED_TOPICS",
                " , com.example.pigeon.beta, , com.example.pigeon.beta ,",
            ),
        ])
        .unwrap();
        assert_eq!(
            config.apns.allowed_topics,
            HashSet::from([
                "com.example.pigeon".to_string(),
                "com.example.pigeon.beta".to_string(),
            ])
        );
        assert!(config_from(&[]).unwrap().apns.allowed_topics.is_empty());
        assert_eq!(
            config_from(&[("APNS_TOPIC", "com.example.pigeon")])
                .unwrap()
                .apns
                .allowed_topics,
            HashSet::from(["com.example.pigeon".to_string()])
        );
    }

    #[test]
    fn valid_config_still_parses() {
        let config = config_from(&[
            ("RELAY_MAX_MESSAGE_BYTES", "1024"),
            ("RELAY_MAX_QUEUE_PER_RECIPIENT", "42"),
            ("RELAY_MAX_SESSION_SEND_QUEUE", "64"),
            ("RELAY_RATE_LIMIT_PER_MIN", "5"),
            ("RELAY_PING_INTERVAL", "30s"),
            ("RELAY_PONG_TIMEOUT", "45s"),
            ("RELAY_MAX_CHALLENGES", "500"),
            ("RELAY_MAX_PUSH_REGISTRATIONS", "1000"),
            ("RELAY_ALLOW_LEGACY_SEND", "on"),
            ("APNS_ENABLED", "off"),
            ("APNS_ENV", "production"),
        ])
        .expect("valid config should parse");

        assert_eq!(config.max_message_bytes, 1024);
        assert_eq!(config.max_queue_per_recipient, 42);
        assert_eq!(config.max_session_send_queue, 64);
        assert_eq!(config.rate_limit_per_min, 5);
        assert_eq!(config.ping_interval, Duration::from_secs(30));
        assert_eq!(config.pong_timeout, Duration::from_secs(45));
        assert_eq!(config.max_concurrent_challenges, 500);
        assert_eq!(config.max_push_registrations, 1000);
        assert!(config.allow_legacy_send);
        assert!(!config.apns.enabled);
        assert_eq!(config.apns.environment, ApnsEnvironment::Production);
    }
}
