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

struct ApnsSigningKey {
    key_id: String,
    key: EncodingKey,
    jwt_cache: Mutex<Option<CachedJwt>>,
}

pub struct ApnsClient {
    http_client: reqwest::Client,
    team_id: String,
    sandbox_signing_key: ApnsSigningKey,
    production_signing_key: ApnsSigningKey,
    default_topic: String,
    default_environment: ApnsEnvironment,
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
struct MessagePushPayload {
    aps: MessagePushApsPayload,
    pigeon_type: &'static str,
}

#[derive(Debug, Serialize)]
struct MessagePushApsPayload {
    #[serde(rename = "content-available")]
    content_available: u8,
    alert: MessagePushAlert,
    sound: &'static str,
}

#[derive(Debug, Serialize)]
struct MessagePushAlert {
    title: &'static str,
    body: &'static str,
}

impl ApnsClient {
    pub fn new(config: &ApnsConfig) -> Result<Self, ApnsError> {
        let sandbox_signing_key = load_signing_key(
            config.sandbox_key_id.as_deref().or(config.key_id.as_deref()),
            config
                .sandbox_private_key_path
                .as_deref()
                .or(config.private_key_path.as_deref()),
            "APNS_SANDBOX_KEY_ID/APNS_KEY_ID",
            "APNS_SANDBOX_PRIVATE_KEY_PATH/APNS_PRIVATE_KEY_PATH",
        )?;
        let production_signing_key = load_signing_key(
            config
                .production_key_id
                .as_deref()
                .or(config.key_id.as_deref()),
            config
                .production_private_key_path
                .as_deref()
                .or(config.private_key_path.as_deref()),
            "APNS_PRODUCTION_KEY_ID/APNS_KEY_ID",
            "APNS_PRODUCTION_PRIVATE_KEY_PATH/APNS_PRIVATE_KEY_PATH",
        )?;

        let http_client = reqwest::Client::builder()
            .build()
            .map_err(ApnsError::Request)?;

        Ok(Self {
            http_client,
            team_id: config
                .team_id
                .clone()
                .ok_or(ApnsError::MissingField("APNS_TEAM_ID"))?,
            sandbox_signing_key,
            production_signing_key,
            default_topic: config
                .topic
                .clone()
                .ok_or(ApnsError::MissingField("APNS_TOPIC"))?,
            default_environment: config.environment,
        })
    }

    pub async fn send_message_push(&self, request: ApnsSendRequest) -> Result<(), ApnsError> {
        let signing_key = match request.environment {
            ApnsEnvironment::Sandbox => &self.sandbox_signing_key,
            ApnsEnvironment::Production => &self.production_signing_key,
        };
        let jwt = self.get_or_refresh_jwt(signing_key)?;

        let topic = request
            .topic_override
            .unwrap_or_else(|| self.default_topic.clone());

        let base_url = match request.environment {
            ApnsEnvironment::Sandbox => "https://api.sandbox.push.apple.com",
            ApnsEnvironment::Production => "https://api.push.apple.com",
        };

        let url = format!("{base_url}/3/device/{}", request.device_token_hex);

        let payload = build_message_push_payload();

        let response = self
            .http_client
            .post(url)
            .header("authorization", format!("bearer {jwt}"))
            .header("apns-topic", topic)
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
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

    fn get_or_refresh_jwt(&self, signing_key: &ApnsSigningKey) -> Result<String, ApnsError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut cache = signing_key
            .jwt_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());

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
        header.kid = Some(signing_key.key_id.clone());

        let token = encode(&header, &claims, &signing_key.key).map_err(ApnsError::Jwt)?;

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

fn load_signing_key(
    key_id: Option<&str>,
    private_key_path: Option<&str>,
    key_id_field: &'static str,
    private_key_path_field: &'static str,
) -> Result<ApnsSigningKey, ApnsError> {
    let key_path = private_key_path.ok_or(ApnsError::MissingField(private_key_path_field))?;
    let key_data = fs::read(key_path).map_err(ApnsError::KeyRead)?;
    let key = EncodingKey::from_ec_pem(&key_data).map_err(ApnsError::KeyParse)?;

    Ok(ApnsSigningKey {
        key_id: key_id
            .map(ToOwned::to_owned)
            .ok_or(ApnsError::MissingField(key_id_field))?,
        key,
        jwt_cache: Mutex::new(None),
    })
}

fn build_message_push_payload() -> MessagePushPayload {
    MessagePushPayload {
        aps: MessagePushApsPayload {
            content_available: 1,
            alert: MessagePushAlert {
                title: "New message",
                body: "You have new messages in Pigeon.",
            },
            sound: "default",
        },
        pigeon_type: "relay_message",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::build_message_push_payload;

    #[test]
    fn serializes_message_push_payload_for_force_quit_delivery() {
        let payload =
            serde_json::to_value(build_message_push_payload()).expect("serialize APNS payload");

        assert_eq!(
            payload,
            json!({
                "aps": {
                    "content-available": 1,
                    "alert": {
                        "title": "New message",
                        "body": "You have new messages in Pigeon."
                    },
                    "sound": "default"
                },
                "pigeon_type": "relay_message"
            })
        );
    }
}
