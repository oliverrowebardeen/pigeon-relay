use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::get;
use chrono::{Duration as ChronoDuration, Utc};
use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::apns::ApnsSendRequest;
use crate::auth;
use crate::config::ApnsEnvironment;
use crate::protocol::{
    AuthHelloPayload, AuthOkPayload, AuthProvePayload, ClientFrame, EmptyPayload, ErrorPayload,
    MessageAcceptedPayload, MessageAckPayload, MessageAckedPayload, MessageDeliverPayload,
    MessageSendPayload, PushRegisterPayload, frame_json, parse_payload,
};
use crate::state::{PushRegistration, RelayState};

pub async fn run_server(
    state: Arc<RelayState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = app(state.clone());

    tokio::spawn(purge_loop(state.clone()));

    let listener = TcpListener::bind(&state.config.relay_addr).await?;
    info!(addr = %state.config.relay_addr, "relay server listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn app(state: Arc<RelayState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/ws", get(ws_handler))
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<RelayState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(state, socket))
}

async fn handle_socket(state: Arc<RelayState>, socket: WebSocket) {
    let connection_id = Uuid::new_v4().to_string();
    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();

    let writer = tokio::spawn(async move {
        while let Some(serialized) = out_rx.recv().await {
            if ws_sender
                .send(Message::Text(serialized.into()))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let mut authenticated_identity: Option<String> = None;
    let mut rate_limit_key = format!("anon:{connection_id}");
    let mut last_pong = Instant::now();
    let mut ping_interval = tokio::time::interval_at(
        tokio::time::Instant::now() + state.config.ping_interval,
        state.config.ping_interval,
    );

    loop {
        tokio::select! {
            _ = ping_interval.tick() => {
                if last_pong.elapsed() > state.config.pong_timeout {
                    warn!(connection_id = %connection_id, "closing stale websocket session due to pong timeout");
                    break;
                }

                if send_frame(&out_tx, "ping", None, EmptyPayload {}).is_err() {
                    break;
                }
            }
            incoming = ws_receiver.next() => {
                let Some(result) = incoming else {
                    break;
                };

                let Ok(message) = result else {
                    break;
                };

                match message {
                    Message::Text(text) => {
                        let Ok(frame) = serde_json::from_str::<ClientFrame>(&text) else {
                            let _ = send_error(&out_tx, None, "bad_frame", "invalid JSON frame");
                            continue;
                        };

                        if !state.allow_request(&rate_limit_key) {
                            let _ = send_error(
                                &out_tx,
                                frame.req_id.clone(),
                                "rate_limited",
                                "rate limit exceeded",
                            );
                            continue;
                        }

                        let should_close = process_frame(
                            &state,
                            &out_tx,
                            &mut authenticated_identity,
                            &mut rate_limit_key,
                            &mut last_pong,
                            frame,
                        )
                        .await;

                        if should_close {
                            break;
                        }
                    }
                    Message::Ping(_) | Message::Pong(_) => {
                        last_pong = Instant::now();
                    }
                    Message::Close(_) => {
                        break;
                    }
                    Message::Binary(_) => {
                        let _ = send_error(&out_tx, None, "bad_frame", "binary frames are not supported");
                    }
                }
            }
        }
    }

    if let Some(identity_hash) = authenticated_identity.as_deref() {
        state.unregister_session(identity_hash);
    }

    drop(out_tx);
    writer.abort();
}

async fn process_frame(
    state: &Arc<RelayState>,
    out_tx: &mpsc::UnboundedSender<String>,
    authenticated_identity: &mut Option<String>,
    rate_limit_key: &mut String,
    last_pong: &mut Instant,
    mut frame: ClientFrame,
) -> bool {
    match frame.frame_type.as_str() {
        "auth_hello" => {
            if authenticated_identity.is_some() {
                let _ = send_error(
                    out_tx,
                    frame.req_id,
                    "already_authenticated",
                    "session already authenticated",
                );
                return false;
            }

            let payload = match parse_payload::<AuthHelloPayload>(&mut frame) {
                Ok(payload) => payload,
                Err(_) => {
                    let _ = send_error(
                        out_tx,
                        frame.req_id,
                        "bad_payload",
                        "invalid auth_hello payload",
                    );
                    return false;
                }
            };

            let challenge = match auth::create_challenge(
                &payload.client_pubkey_b64,
                state.config.challenge_ttl,
            ) {
                Ok(challenge) => challenge,
                Err(_) => {
                    let _ = send_error(
                        out_tx,
                        frame.req_id,
                        "auth_failed",
                        "invalid client public key",
                    );
                    return true;
                }
            };

            let (challenge_payload, challenge_record) = challenge;
            state
                .challenges
                .insert(challenge_record.challenge_id.clone(), challenge_record);

            let _ = send_frame(out_tx, "auth_challenge", frame.req_id, challenge_payload);
            false
        }
        "auth_prove" => {
            if authenticated_identity.is_some() {
                let _ = send_error(
                    out_tx,
                    frame.req_id,
                    "already_authenticated",
                    "session already authenticated",
                );
                return false;
            }

            let payload = match parse_payload::<AuthProvePayload>(&mut frame) {
                Ok(payload) => payload,
                Err(_) => {
                    let _ = send_error(
                        out_tx,
                        frame.req_id,
                        "bad_payload",
                        "invalid auth_prove payload",
                    );
                    return false;
                }
            };

            let Some((_, challenge_record)) = state.challenges.remove(&payload.challenge_id) else {
                let _ = send_error(
                    out_tx,
                    frame.req_id,
                    "auth_failed",
                    "challenge not found or already used",
                );
                return true;
            };

            let identity_hash = match auth::verify_proof(&challenge_record, &payload.proof_b64) {
                Ok(hash) => hash,
                Err(_) => {
                    let _ = send_error(
                        out_tx,
                        frame.req_id,
                        "auth_failed",
                        "proof verification failed",
                    );
                    return true;
                }
            };

            let session_expires_at = Utc::now()
                + ChronoDuration::from_std(state.config.session_ttl)
                    .unwrap_or(ChronoDuration::hours(24));

            state.register_session(
                identity_hash.clone(),
                out_tx.clone(),
                state.config.session_ttl,
            );

            let _ = send_frame(
                out_tx,
                "auth_ok",
                frame.req_id,
                AuthOkPayload {
                    identity_hash_hex: identity_hash.clone(),
                    session_expires_at_ms: session_expires_at.timestamp_millis(),
                },
            );

            for queued in state.queue.drain_for_recipient(&identity_hash) {
                let payload = MessageDeliverPayload {
                    message_id: queued.message_id.to_string(),
                    sender_hash_hex: queued.sender_hash,
                    envelope_b64: queued.envelope_b64,
                    queued_at_ms: queued.queued_at.timestamp_millis(),
                };
                let _ = send_frame(out_tx, "msg_deliver", None, payload);
            }

            for pending_ack in state.take_pending_acks(&identity_hash) {
                let _ = send_frame(out_tx, "msg_acked", None, pending_ack);
            }

            *rate_limit_key = identity_hash.clone();
            *authenticated_identity = Some(identity_hash);

            false
        }
        "msg_send" => {
            let Some(sender_hash) = authenticated_identity.as_ref() else {
                let _ = send_error(
                    out_tx,
                    frame.req_id,
                    "unauthorized",
                    "authenticate before sending messages",
                );
                return false;
            };

            let payload = match parse_payload::<MessageSendPayload>(&mut frame) {
                Ok(payload) => payload,
                Err(_) => {
                    let _ = send_error(
                        out_tx,
                        frame.req_id,
                        "bad_payload",
                        "invalid msg_send payload",
                    );
                    return false;
                }
            };

            let message_id = match Uuid::parse_str(&payload.message_id) {
                Ok(id) => id,
                Err(_) => {
                    let _ = send_error(out_tx, frame.req_id, "bad_payload", "invalid message_id");
                    return false;
                }
            };

            let b64_len = payload.envelope_b64.len();
            if b64_len < 4 || b64_len % 4 != 0 {
                let _ = send_error(
                    out_tx,
                    frame.req_id,
                    "bad_payload",
                    "envelope_b64 must be valid base64",
                );
                return false;
            }
            let padding = payload
                .envelope_b64
                .as_bytes()
                .iter()
                .rev()
                .take_while(|&&b| b == b'=')
                .count();
            let decoded_len = (b64_len / 4) * 3 - padding;

            if decoded_len > state.config.max_message_bytes {
                let _ = send_error(
                    out_tx,
                    frame.req_id,
                    "too_large",
                    "message exceeds max size",
                );
                return false;
            }

            let (queued, depth) = state.queue.enqueue(
                sender_hash.clone(),
                payload.recipient_hash_hex.clone(),
                message_id,
                payload.envelope_b64.clone(),
            );

            let accepted_payload = MessageAcceptedPayload {
                message_id: payload.message_id.clone(),
                queued,
                queue_depth: depth,
            };
            let _ = send_frame(out_tx, "msg_accepted", frame.req_id, accepted_payload);

            if let Some(recipient_session) = state.sessions.get(&payload.recipient_hash_hex) {
                let deliver_payload = MessageDeliverPayload {
                    message_id: payload.message_id,
                    sender_hash_hex: sender_hash.clone(),
                    envelope_b64: payload.envelope_b64,
                    queued_at_ms: Utc::now().timestamp_millis(),
                };
                if send_frame(
                    &recipient_session.sender,
                    "msg_deliver",
                    None,
                    deliver_payload,
                )
                .is_err()
                {
                    drop(recipient_session);
                    state.unregister_session(&payload.recipient_hash_hex);
                    warn!(
                        recipient = %hash_prefix(&payload.recipient_hash_hex),
                        "live delivery failed for stale session; falling back to APNS"
                    );
                    maybe_trigger_apns(state, &payload.recipient_hash_hex).await;
                }
            } else {
                maybe_trigger_apns(state, &payload.recipient_hash_hex).await;
            }

            false
        }
        "msg_ack" => {
            let Some(recipient_hash) = authenticated_identity.as_ref() else {
                let _ = send_error(
                    out_tx,
                    frame.req_id,
                    "unauthorized",
                    "authenticate before acking messages",
                );
                return false;
            };

            let payload = match parse_payload::<MessageAckPayload>(&mut frame) {
                Ok(payload) => payload,
                Err(_) => {
                    let _ = send_error(
                        out_tx,
                        frame.req_id,
                        "bad_payload",
                        "invalid msg_ack payload",
                    );
                    return false;
                }
            };

            let message_id = match Uuid::parse_str(&payload.message_id) {
                Ok(id) => id,
                Err(_) => {
                    let _ = send_error(out_tx, frame.req_id, "bad_payload", "invalid message_id");
                    return false;
                }
            };

            if let Some(acked_message) = state.queue.ack_message(recipient_hash, message_id) {
                let ack_payload = MessageAckedPayload {
                    message_id: payload.message_id,
                    acked_at_ms: Utc::now().timestamp_millis(),
                };

                if let Some(sender_session) = state.sessions.get(&acked_message.sender_hash) {
                    if send_frame(
                        &sender_session.sender,
                        "msg_acked",
                        None,
                        ack_payload.clone(),
                    )
                    .is_err()
                    {
                        drop(sender_session);
                        state.unregister_session(&acked_message.sender_hash);
                        state.store_pending_ack(&acked_message.sender_hash, ack_payload);
                    }
                } else {
                    state.store_pending_ack(&acked_message.sender_hash, ack_payload);
                }
            }

            false
        }
        "push_register" => {
            let Some(identity_hash) = authenticated_identity.as_ref() else {
                let _ = send_error(
                    out_tx,
                    frame.req_id,
                    "unauthorized",
                    "authenticate before registering push token",
                );
                return false;
            };

            let payload = match parse_payload::<PushRegisterPayload>(&mut frame) {
                Ok(payload) => payload,
                Err(_) => {
                    let _ = send_error(
                        out_tx,
                        frame.req_id,
                        "bad_payload",
                        "invalid push_register payload",
                    );
                    return false;
                }
            };

            if payload.device_token_hex.len() > 200
                || !payload
                    .device_token_hex
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit())
            {
                let _ = send_error(
                    out_tx,
                    frame.req_id,
                    "bad_payload",
                    "device_token_hex must be valid hex",
                );
                return false;
            }

            let apns_env = payload
                .apns_env
                .as_deref()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| {
                    state
                        .apns_client
                        .as_ref()
                        .map_or(ApnsEnvironment::default(), |client| {
                            client.default_environment()
                        })
                });
            let has_topic_override = payload
                .topic
                .as_ref()
                .is_some_and(|topic| !topic.trim().is_empty());

            state.push_tokens.insert(
                identity_hash.clone(),
                PushRegistration {
                    device_token_hex: payload.device_token_hex,
                    apns_env,
                    topic_override: payload.topic.and_then(|topic| {
                        let trimmed = topic.trim();
                        (!trimmed.is_empty()).then(|| trimmed.to_string())
                    }),
                    last_push_at: None,
                },
            );
            info!(
                identity = %hash_prefix(identity_hash),
                apns_env = ?apns_env,
                has_topic_override,
                "registered APNS push token"
            );

            false
        }
        "pong" => {
            *last_pong = Instant::now();
            false
        }
        "ping" => {
            let _ = send_frame(out_tx, "pong", frame.req_id, EmptyPayload {});
            false
        }
        _ => {
            let _ = send_error(out_tx, frame.req_id, "bad_frame", "unsupported frame type");
            false
        }
    }
}

async fn maybe_trigger_apns(state: &Arc<RelayState>, recipient_hash: &str) {
    let Some(apns_client) = &state.apns_client else {
        return;
    };

    if !state.maybe_record_push(recipient_hash, Duration::from_secs(30)) {
        return;
    }

    let Some(push_registration) = state
        .push_tokens
        .get(recipient_hash)
        .map(|item| item.clone())
    else {
        return;
    };

    let request = ApnsSendRequest {
        device_token_hex: push_registration.device_token_hex,
        environment: push_registration.apns_env,
        topic_override: push_registration.topic_override,
    };

    let apns_client = apns_client.clone();
    let recipient_hash = recipient_hash.to_string();
    tokio::spawn(async move {
        info!(
            recipient = %hash_prefix(&recipient_hash),
            environment = ?request.environment,
            has_topic_override = request.topic_override.is_some(),
            "sending APNS push"
        );
        if let Err(error) = apns_client.send_message_push(request).await {
            warn!(?error, "failed to send APNS message push");
        }
    });
}

fn hash_prefix(value: &str) -> &str {
    let prefix_len = value.len().min(8);
    &value[..prefix_len]
}

fn send_frame<T>(
    tx: &mpsc::UnboundedSender<String>,
    frame_type: &'static str,
    req_id: Option<String>,
    payload: T,
) -> Result<(), ()>
where
    T: serde::Serialize,
{
    let serialized = frame_json(frame_type, req_id, payload).map_err(|_| ())?;
    tx.send(serialized).map_err(|_| ())
}

fn send_error(
    tx: &mpsc::UnboundedSender<String>,
    req_id: Option<String>,
    code: &str,
    message: &str,
) -> Result<(), ()> {
    send_frame(
        tx,
        "error",
        req_id,
        ErrorPayload {
            code: code.to_string(),
            message: message.to_string(),
        },
    )
}

async fn purge_loop(state: Arc<RelayState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));

    loop {
        interval.tick().await;
        state.purge_expired();
        info!(
            sessions = state.sessions.len(),
            challenges = state.challenges.len(),
            "purged expired state"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use futures::{SinkExt, StreamExt};
    use hkdf::Hkdf;
    use hmac::{Hmac, Mac};
    use rand::RngCore;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::Message;
    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::auth;
    use crate::config::{ApnsConfig, ApnsEnvironment, Config};

    use super::*;

    type HmacSha256 = Hmac<Sha256>;
    type TestSocket = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    struct AuthenticatedClient {
        socket: TestSocket,
        identity_hash: String,
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn same_ip_clients_have_isolated_authenticated_rate_limits() {
        let (addr, server_task) = spawn_test_server(test_config(2)).await;

        let mut client_a = connect_authenticated_client(addr).await;
        let mut client_b = connect_authenticated_client(addr).await;

        send_json(
            &mut client_a.socket,
            json!({
                "type": "ping",
                "payload": {}
            }),
        )
        .await;
        let pong = recv_json(&mut client_a.socket).await;
        assert_eq!(pong["type"], "pong");

        send_json(
            &mut client_a.socket,
            json!({
                "type": "ping",
                "payload": {}
            }),
        )
        .await;
        let pong = recv_json(&mut client_a.socket).await;
        assert_eq!(pong["type"], "pong");

        send_json(
            &mut client_a.socket,
            json!({
                "type": "ping",
                "payload": {}
            }),
        )
        .await;
        let rate_limited = recv_json(&mut client_a.socket).await;
        assert_eq!(rate_limited["type"], "error");
        assert_eq!(rate_limited["payload"]["code"], "rate_limited");

        send_json(
            &mut client_b.socket,
            json!({
                "type": "ping",
                "payload": {}
            }),
        )
        .await;
        let pong = recv_json(&mut client_b.socket).await;
        assert_eq!(pong["type"], "pong");

        server_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn same_ip_clients_route_messages_to_the_correct_authenticated_identity() {
        let (addr, server_task) = spawn_test_server(test_config(10)).await;

        let mut sender = connect_authenticated_client(addr).await;
        let mut recipient = connect_authenticated_client(addr).await;
        let message_id = Uuid::new_v4().to_string();
        let envelope_b64 = STANDARD.encode(b"opaque-envelope");

        send_json(
            &mut sender.socket,
            json!({
                "type": "msg_send",
                "payload": {
                    "message_id": message_id,
                    "recipient_hash_hex": recipient.identity_hash,
                    "envelope_b64": envelope_b64
                }
            }),
        )
        .await;

        let accepted = recv_json(&mut sender.socket).await;
        assert_eq!(accepted["type"], "msg_accepted");
        assert_eq!(accepted["payload"]["queued"], true);

        let deliver = recv_json(&mut recipient.socket).await;
        assert_eq!(deliver["type"], "msg_deliver");
        assert_eq!(deliver["payload"]["message_id"], message_id);
        assert_eq!(deliver["payload"]["sender_hash_hex"], sender.identity_hash);
        assert_eq!(deliver["payload"]["envelope_b64"], envelope_b64);

        server_task.abort();
    }

    async fn spawn_test_server(config: Config) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let state = Arc::new(RelayState::new(config, None));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("read test server addr");
        let router = app(state);
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve test router");
        });
        (addr, handle)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_live_delivery_cleans_up_stale_session_and_keeps_message_queued() {
        let state = Arc::new(RelayState::new(test_config(10), None));
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();
        let (dead_tx, dead_rx) = mpsc::unbounded_channel::<String>();
        drop(dead_rx);

        state.register_session(
            "recipient-hash".to_string(),
            dead_tx,
            Duration::from_secs(60),
        );

        let mut authenticated_identity = Some("sender-hash".to_string());
        let mut rate_limit_key = "sender-hash".to_string();
        let mut last_pong = Instant::now();

        let should_close = process_frame(
            &state,
            &out_tx,
            &mut authenticated_identity,
            &mut rate_limit_key,
            &mut last_pong,
            ClientFrame {
                frame_type: "msg_send".to_string(),
                req_id: Some("req-1".to_string()),
                payload: serde_json::json!({
                    "message_id": Uuid::new_v4().to_string(),
                    "recipient_hash_hex": "recipient-hash",
                    "envelope_b64": STANDARD.encode(b"opaque-envelope"),
                }),
            },
        )
        .await;

        assert!(!should_close);
        assert!(state.sessions.get("recipient-hash").is_none());

        let accepted = out_rx.recv().await.expect("msg_accepted");
        let accepted: serde_json::Value =
            serde_json::from_str(&accepted).expect("parse msg_accepted");
        assert_eq!(accepted["type"], "msg_accepted");

        let queued = state.queue.drain_for_recipient("recipient-hash");
        assert_eq!(queued.len(), 1);
    }

    async fn connect_authenticated_client(addr: SocketAddr) -> AuthenticatedClient {
        let url = format!("ws://{addr}/v1/ws");
        let (mut socket, _) = connect_async(url).await.expect("connect websocket");

        let mut client_secret_bytes = [0_u8; 32];
        rand::rng().fill_bytes(&mut client_secret_bytes);
        let client_secret = StaticSecret::from(client_secret_bytes);
        let client_public = PublicKey::from(&client_secret);
        let client_pubkey_b64 = STANDARD.encode(client_public.as_bytes());

        send_json(
            &mut socket,
            json!({
                "type": "auth_hello",
                "payload": {
                    "client_pubkey_b64": client_pubkey_b64
                }
            }),
        )
        .await;

        let challenge = recv_json(&mut socket).await;
        assert_eq!(challenge["type"], "auth_challenge");
        let payload = &challenge["payload"];
        let challenge_id = payload["challenge_id"].as_str().expect("challenge_id");
        let nonce = STANDARD
            .decode(payload["nonce_b64"].as_str().expect("nonce_b64"))
            .expect("decode nonce");
        let server_pubkey_bytes: [u8; 32] = STANDARD
            .decode(
                payload["server_pubkey_b64"]
                    .as_str()
                    .expect("server_pubkey_b64"),
            )
            .expect("decode server pubkey")
            .try_into()
            .expect("server pubkey length");
        let server_public = PublicKey::from(server_pubkey_bytes);

        let shared_secret = client_secret.diffie_hellman(&server_public);
        let hkdf = Hkdf::<Sha256>::new(Some(b"pigeon-relay-auth-v1"), shared_secret.as_bytes());
        let mut auth_key = [0_u8; 32];
        let mut info =
            Vec::with_capacity(challenge_id.len() + nonce.len() + client_public.as_bytes().len());
        info.extend_from_slice(challenge_id.as_bytes());
        info.extend_from_slice(&nonce);
        info.extend_from_slice(client_public.as_bytes());
        hkdf.expand(&info, &mut auth_key).expect("derive auth key");

        let issued_at_ms = payload["issued_at_ms"].as_i64().expect("issued_at_ms");
        let signed_message = auth::proof_message(challenge_id, issued_at_ms);
        let mut mac = HmacSha256::new_from_slice(&auth_key).expect("init hmac");
        mac.update(&signed_message);
        let proof_b64 = STANDARD.encode(mac.finalize().into_bytes());

        send_json(
            &mut socket,
            json!({
                "type": "auth_prove",
                "payload": {
                    "challenge_id": challenge_id,
                    "proof_b64": proof_b64
                }
            }),
        )
        .await;

        let auth_ok = recv_json(&mut socket).await;
        assert_eq!(auth_ok["type"], "auth_ok");
        let identity_hash = auth_ok["payload"]["identity_hash_hex"]
            .as_str()
            .expect("identity_hash_hex")
            .to_string();

        let expected_identity_hash = hex::encode(Sha256::digest(client_public.as_bytes()));
        assert_eq!(identity_hash, expected_identity_hash);

        AuthenticatedClient {
            socket,
            identity_hash,
        }
    }

    async fn send_json(socket: &mut TestSocket, value: Value) {
        socket
            .send(Message::Text(value.to_string()))
            .await
            .expect("send websocket text frame");
    }

    async fn recv_json(socket: &mut TestSocket) -> Value {
        loop {
            let frame = socket
                .next()
                .await
                .expect("websocket frame")
                .expect("websocket message");

            match frame {
                Message::Text(text) => {
                    let value: Value =
                        serde_json::from_str(&text).expect("decode websocket json frame");
                    if value["type"] == "ping" {
                        send_json(
                            socket,
                            json!({
                                "type": "pong",
                                "payload": {}
                            }),
                        )
                        .await;
                        continue;
                    }
                    return value;
                }
                Message::Ping(payload) => {
                    socket
                        .send(Message::Pong(payload))
                        .await
                        .expect("reply pong");
                }
                Message::Pong(_) => {}
                Message::Close(frame) => panic!("unexpected websocket close: {frame:?}"),
                other => panic!("unexpected websocket frame: {other:?}"),
            }
        }
    }

    fn test_config(rate_limit_per_min: u32) -> Config {
        Config {
            relay_addr: "127.0.0.1:0".to_string(),
            message_ttl: Duration::from_secs(3600),
            max_message_bytes: 65_536,
            max_queue_per_recipient: 500,
            challenge_ttl: Duration::from_secs(30),
            session_ttl: Duration::from_secs(3600),
            rate_limit_per_min,
            ping_interval: Duration::from_secs(300),
            pong_timeout: Duration::from_secs(600),
            apns: ApnsConfig {
                enabled: false,
                team_id: None,
                key_id: None,
                private_key_path: None,
                sandbox_key_id: None,
                sandbox_private_key_path: None,
                production_key_id: None,
                production_private_key_path: None,
                topic: None,
                environment: ApnsEnvironment::Sandbox,
            },
        }
    }
}
