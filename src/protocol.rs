use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct ClientFrame {
    #[serde(rename = "type")]
    pub frame_type: String,
    #[serde(default)]
    pub req_id: Option<String>,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Debug, Serialize)]
pub struct ServerFrame<T>
where
    T: Serialize,
{
    #[serde(rename = "type")]
    pub frame_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub req_id: Option<String>,
    pub payload: T,
}

#[derive(Debug, Deserialize)]
pub struct AuthHelloPayload {
    pub client_pubkey_b64: String,
}

#[derive(Debug, Serialize)]
pub struct AuthChallengePayload {
    pub challenge_id: String,
    pub server_pubkey_b64: String,
    pub nonce_b64: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Debug, Deserialize)]
pub struct AuthProvePayload {
    pub challenge_id: String,
    pub proof_b64: String,
}

#[derive(Debug, Serialize)]
pub struct AuthOkPayload {
    pub identity_hash_hex: String,
    pub session_expires_at_ms: i64,
}

#[derive(Debug, Deserialize)]
pub struct MessageSendPayload {
    pub message_id: String,
    pub recipient_hash_hex: String,
    pub envelope_b64: String,
}

#[derive(Debug, Serialize)]
pub struct MessageAcceptedPayload {
    pub message_id: String,
    pub queued: bool,
    pub queue_depth: usize,
}

#[derive(Debug, Serialize, Clone)]
pub struct MessageDeliverPayload {
    pub message_id: String,
    pub sender_hash_hex: String,
    pub envelope_b64: String,
    pub queued_at_ms: i64,
}

#[derive(Debug, Deserialize)]
pub struct MessageAckPayload {
    pub message_id: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct MessageAckedPayload {
    pub message_id: String,
    pub acked_at_ms: i64,
}

#[derive(Debug, Deserialize)]
pub struct PushRegisterPayload {
    pub device_token_hex: String,
    pub apns_env: Option<String>,
    pub topic: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ErrorPayload {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct EmptyPayload {}

pub fn parse_payload<T>(frame: &ClientFrame) -> Result<T, serde_json::Error>
where
    T: DeserializeOwned,
{
    serde_json::from_value(frame.payload.clone())
}

pub fn frame_json<T>(
    frame_type: &'static str,
    req_id: Option<String>,
    payload: T,
) -> Result<String, serde_json::Error>
where
    T: Serialize,
{
    let frame = ServerFrame {
        frame_type,
        req_id,
        payload,
    };
    serde_json::to_string(&frame)
}
