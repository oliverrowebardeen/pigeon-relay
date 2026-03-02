use std::fs;

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use reqwest::StatusCode;
use serde::Serialize;
use thiserror::Error;

use crate::config::{ApnsConfig, ApnsEnvironment};

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
}

#[derive(Debug, Clone)]
pub struct ApnsClient {
    http_client: reqwest::Client,
    team_id: String,
    key_id: String,
    key: EncodingKey,
    default_topic: String,
    default_environment: ApnsEnvironment,
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
            .expect("validated in config loader");
        let key_data = fs::read(key_path).map_err(ApnsError::KeyRead)?;
        let key = EncodingKey::from_ec_pem(&key_data).map_err(ApnsError::KeyParse)?;

        let http_client = reqwest::Client::builder()
            .build()
            .map_err(ApnsError::Request)?;

        Ok(Self {
            http_client,
            team_id: config.team_id.clone().expect("validated in config loader"),
            key_id: config.key_id.clone().expect("validated in config loader"),
            key,
            default_topic: config.topic.clone().expect("validated in config loader"),
            default_environment: config.environment,
        })
    }

    pub async fn send_silent_push(&self, request: ApnsSendRequest) -> Result<(), ApnsError> {
        let jwt = self.build_jwt()?;

        let topic = request
            .topic_override
            .unwrap_or_else(|| self.default_topic.clone());
        let environment = request.environment;

        let base_url = match environment {
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

    fn build_jwt(&self) -> Result<String, ApnsError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as usize;

        let claims = JwtClaims {
            iss: self.team_id.clone(),
            iat: now,
        };

        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());

        encode(&header, &claims, &self.key).map_err(ApnsError::Jwt)
    }

    pub fn default_environment(&self) -> ApnsEnvironment {
        self.default_environment
    }
}
