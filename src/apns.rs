use std::fs;
use std::sync::Mutex;

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use reqwest::StatusCode;
use serde::Serialize;
use thiserror::Error;

use crate::config::{ApnsConfig, ApnsEnvironment};

const JWT_REFRESH_SECS: u64 = 50 * 60; // refresh 10 min before Apple's 60-min expiry

#[derive(Debug, Error)]
pub enum ApnsError {
    #[error("failed to read APNS private key: {0}")]
    KeyRead(std::io::Error),
    #[error("failed to parse APNS private key: {0}")]
    KeyParse(jsonwebtoken::errors::Error),
    #[error("failed to encode APNS JWT: {0}")]
    Jwt(jsonwebtoken::errors::Error),
    #[error("APNS request failed: {0}")]
    Request(reqwest::Error),
    #[error("APNS rejected push: status={status}, body={body}")]
    Rejected { status: StatusCode, body: String },
    #[error("missing APNS config field: {0}")]
    MissingField(&'static str),
}

struct CachedJwt {
    token: String,
    issued_at: u64,
}

pub struct ApnsClient {
    http_client: reqwest::Client,
    team_id: String,
    key_id: String,
    key: EncodingKey,
    default_topic: String,
    default_environment: ApnsEnvironment,
    jwt_cache: Mutex<Option<CachedJwt>>,
}

impl std::fmt::Debug for ApnsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApnsClient")
            .field("team_id", &self.team_id)
            .field("default_topic", &self.default_topic)
            .field("default_environment", &self.default_environment)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct ApnsSendRequest {
    pub device_token_hex: String,
    pub environment: ApnsEnvironment,
    pub topic_override: Option<String>,
}

#[derive(Debug, Serialize)]
struct JwtClaims {
    iss: String,
    iat: usize,
}

#[derive(Debug, Serialize)]
struct SilentPushPayload {
    aps: ApsPayload,
}

#[derive(Debug, Serialize)]
struct ApsPayload {
    #[serde(rename = "content-available")]
    content_available: u8,
}

impl ApnsClient {
    pub fn new(config: &ApnsConfig) -> Result<Self, ApnsError> {
        let key_path = config
            .private_key_path
            .as_deref()
            .ok_or(ApnsError::MissingField("APNS_PRIVATE_KEY_PATH"))?;
        let key_data = fs::read(key_path).map_err(ApnsError::KeyRead)?;
        let key = EncodingKey::from_ec_pem(&key_data).map_err(ApnsError::KeyParse)?;

        let http_client = reqwest::Client::builder()
            .build()
            .map_err(ApnsError::Request)?;

        Ok(Self {
            http_client,
            team_id: config
                .team_id
                .clone()
                .ok_or(ApnsError::MissingField("APNS_TEAM_ID"))?,
            key_id: config
                .key_id
                .clone()
                .ok_or(ApnsError::MissingField("APNS_KEY_ID"))?,
            key,
            default_topic: config
                .topic
                .clone()
                .ok_or(ApnsError::MissingField("APNS_TOPIC"))?,
            default_environment: config.environment,
            jwt_cache: Mutex::new(None),
        })
    }

    pub async fn send_silent_push(&self, request: ApnsSendRequest) -> Result<(), ApnsError> {
        let jwt = self.get_or_refresh_jwt()?;

        let topic = request
            .topic_override
            .unwrap_or_else(|| self.default_topic.clone());

        let base_url = match request.environment {
            ApnsEnvironment::Sandbox => "https://api.sandbox.push.apple.com",
            ApnsEnvironment::Production => "https://api.push.apple.com",
        };

        let url = format!("{base_url}/3/device/{}", request.device_token_hex);

        let payload = SilentPushPayload {
            aps: ApsPayload {
                content_available: 1,
            },
        };

        let response = self
            .http_client
            .post(url)
            .header("authorization", format!("bearer {jwt}"))
            .header("apns-topic", topic)
            .header("apns-push-type", "background")
            .header("apns-priority", "5")
            .json(&payload)
            .send()
            .await
            .map_err(ApnsError::Request)?;

        if response.status().is_success() {
            return Ok(());
        }

        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unavailable>".to_string());

        Err(ApnsError::Rejected { status, body })
    }

    fn get_or_refresh_jwt(&self) -> Result<String, ApnsError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut cache = self.jwt_cache.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(cached) = cache.as_ref() {
            if now.saturating_sub(cached.issued_at) < JWT_REFRESH_SECS {
                return Ok(cached.token.clone());
            }
        }

        let claims = JwtClaims {
            iss: self.team_id.clone(),
            iat: now as usize,
        };

        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());

        let token = encode(&header, &claims, &self.key).map_err(ApnsError::Jwt)?;

        *cache = Some(CachedJwt {
            token: token.clone(),
            issued_at: now,
        });

        Ok(token)
    }

    pub fn default_environment(&self) -> ApnsEnvironment {
        self.default_environment
    }
}
