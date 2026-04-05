use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::get;
use chrono::{Duration as ChronoDuration, Utc};
use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use uuid::Uuid;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::StatusCode;

use crate::apns::{ApnsError, ApnsSendRequest};
use crate::auth;
use crate::config::ApnsEnvironment;
use crate::protocol::{
    AuthHelloPayload, AuthOkPayload, AuthProvePayload, ClientFrame, EmptyPayload, ErrorPayload,
    MessageAcceptedPayload, MessageDeliverPayload, MessageSendPayload, PushRegisterPayload,
    frame_json, parse_payload,
};
use crate::state::{OutboundFrame, PushRegistration, RelayState};

#[derive(Debug, Clone, Copy, PartialEq)]
enum ConnectionRole {
    Undecided,
    Receive,
    Send,
}

pub async fn run_server(
    state: Arc<RelayState>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = app(state.clone());

    tokio::spawn(purge_loop(state.clone()));

    let listener = TcpListener::bind(&state.config.relay_addr).await?;
    info!(addr = %state.config.relay_addr, "relay server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
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
    ws.max_message_size(max_ws_frame_size(state.config.max_message_bytes))
        .on_upgrade(move |socket| handle_socket(state, socket))
}

fn max_ws_frame_size(max_message_bytes: usize) -> usize {
    // `msg_send` carries the envelope base64-encoded inside a JSON text frame.
    let envelope_b64_bytes = max_message_bytes.div_ceil(3).saturating_mul(4);
    envelope_b64_bytes.saturating_add(1024)
}

async fn handle_socket(state: Arc<RelayState>, socket: WebSocket) {
    let connection_id = Uuid::new_v4().to_string();
    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (out_tx, mut out_rx) = mpsc::channel::<OutboundFrame>(state.config.max_session_send_queue);

    let writer = tokio::spawn(async move {
        while let Some(outbound) = out_rx.recv().await {
            let close_after_send = outbound.close_after_send;
            let send_result = ws_sender
                .send(Message::Text(outbound.serialized.into()))
                .await
                .map_err(|_| ());
            let send_failed = send_result.is_err();
            if let Some(delivery_tx) = outbound.delivery_tx {
                let _ = delivery_tx.send(send_result);
            }
            if send_failed {
                break;
            }

            if let Some(close_after_send) = close_after_send {
                let _ = ws_sender
                    .send(Message::Close(Some(CloseFrame {
                        code: close_after_send.code,
                        reason: close_after_send.reason.into(),
                    })))
                    .await;
                break;
            }
        }
    });

    let mut authenticated_identity: Option<String> = None;
    let mut rate_limit_key = format!("anon:{connection_id}");
    let mut connection_role = ConnectionRole::Undecided;
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

                if send_frame(&out_tx, "ping", None, EmptyPayload {})
                    .await
                    .is_err()
                {
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
                            let _ = send_error(&out_tx, None, "bad_frame", "invalid JSON frame").await;
                            continue;
                        };

                        if frame.frame_type != "pong"
                            && !state.allow_request(&rate_limit_key)
                        {
                            let _ = send_error(
                                &out_tx,
                                frame.req_id.clone(),
                                "rate_limited",
                                "rate limit exceeded",
                            )
                            .await;
                            continue;
                        }

                        let should_close = process_frame(
                            &state,
                            &out_tx,
                            &mut authenticated_identity,
                            &mut rate_limit_key,
                            &mut last_pong,
                            &mut connection_role,
                            &state.config.allow_legacy_send,
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
                        let _ = send_error(
                            &out_tx,
                            None,
                            "bad_frame",
                            "binary frames are not supported",
                        )
                        .await;
                    }
                }
            }
        }
    }

    if let Some(identity_hash) = authenticated_identity.as_deref() {
        state.unregister_session(identity_hash);
    }

    drop(out_tx);
    let _ = tokio::time::timeout(Duration::from_secs(5), writer).await;
}

#[allow(clippy::too_many_arguments)]
async fn process_frame(
    state: &Arc<RelayState>,
    out_tx: &mpsc::Sender<OutboundFrame>,
    authenticated_identity: &mut Option<String>,
    rate_limit_key: &mut String,
    last_pong: &mut Instant,
    connection_role: &mut ConnectionRole,
    allow_legacy_send: &bool,
    mut frame: ClientFrame,
) -> bool {
    if *connection_role == ConnectionRole::Undecided {
        match frame.frame_type.as_str() {
            "auth_hello" => *connection_role = ConnectionRole::Receive,
            "msg_send" => *connection_role = ConnectionRole::Send,
            "pong" | "ping" => {}
            _ => {
                let _ = send_error(
                    out_tx,
                    frame.req_id.clone(),
                    "bad_frame",
                    "first frame must be auth_hello or msg_send",
                )
                .await;
                return false;
            }
        }
    }

    match frame.frame_type.as_str() {
        "auth_hello" => {
            if *connection_role == ConnectionRole::Send {
                let _ = send_error(
                    out_tx,
                    frame.req_id,
                    "bad_frame",
                    "auth not allowed on send connections",
                )
                .await;
                return false;
            }

            if state.challenges.len() >= state.config.max_concurrent_challenges {
                let _ = send_error(
                    out_tx,
                    frame.req_id,
                    "server_busy",
                    "too many pending challenges",
                )
                .await;
                return false;
            }

            if authenticated_identity.is_some() {
                let _ = send_error(
                    out_tx,
                    frame.req_id,
                    "already_authenticated",
                    "session already authenticated",
                )
                .await;
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
                    )
                    .await;
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
                    )
                    .await;
                    return true;
                }
            };

            let (challenge_payload, challenge_record) = challenge;
            state
                .challenges
                .insert(challenge_record.challenge_id.clone(), challenge_record);

            let _ = send_frame(out_tx, "auth_challenge", frame.req_id, challenge_payload).await;
            false
        }
        "auth_prove" => {
            if *connection_role == ConnectionRole::Send {
                let _ = send_error(
                    out_tx,
                    frame.req_id,
                    "bad_frame",
                    "auth not allowed on send connections",
                )
                .await;
                return false;
            }

            if authenticated_identity.is_some() {
                let _ = send_error(
                    out_tx,
                    frame.req_id,
                    "already_authenticated",
                    "session already authenticated",
                )
                .await;
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
                    )
                    .await;
                    return false;
                }
            };

            let Some((_, challenge_record)) = state.challenges.remove(&payload.challenge_id) else {
                let _ = send_error(
                    out_tx,
                    frame.req_id,
                    "auth_failed",
                    "challenge not found or already used",
                )
                .await;
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
                    )
                    .await;
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

            if send_frame(
                out_tx,
                "auth_ok",
                frame.req_id,
                AuthOkPayload {
                    identity_hash_hex: identity_hash.clone(),
                    session_expires_at_ms: session_expires_at.timestamp_millis(),
                },
            )
            .await
            .is_err()
            {
                state.unregister_session(&identity_hash);
                return true;
            }

            if deliver_queued_messages(state, &identity_hash, out_tx)
                .await
                .is_err()
            {
                state.unregister_session(&identity_hash);
                return true;
            }

            *rate_limit_key = identity_hash.clone();
            *authenticated_identity = Some(identity_hash);

            false
        }
        "msg_send" => {
            if *connection_role == ConnectionRole::Receive && !*allow_legacy_send {
                let _ = send_error(
                    out_tx,
                    frame.req_id,
                    "unauthorized",
                    "msg_send not allowed on receive connections",
                )
                .await;
                return false;
            }

            if *connection_role == ConnectionRole::Receive
                && *allow_legacy_send
                && authenticated_identity.is_none()
            {
                let _ = send_error(
                    out_tx,
                    frame.req_id,
                    "unauthorized",
                    "authenticate before sending messages",
                )
                .await;
                return false;
            }

            let payload = match parse_payload::<MessageSendPayload>(&mut frame) {
                Ok(payload) => payload,
                Err(_) => {
                    let _ = send_error(
                        out_tx,
                        frame.req_id,
                        "bad_payload",
                        "invalid msg_send payload",
                    )
                    .await;
                    return false;
                }
            };

            if !is_valid_identity_hash(&payload.recipient_hash_hex) {
                let _ = send_error(
                    out_tx,
                    frame.req_id,
                    "bad_payload",
                    "recipient_hash_hex must be a 64-character hex string",
                )
                .await;
                return false;
            }

            let message_id = match Uuid::parse_str(&payload.message_id) {
                Ok(id) => id,
                Err(_) => {
                    let _ =
                        send_error(out_tx, frame.req_id, "bad_payload", "invalid message_id").await;
                    return false;
                }
            };

            let envelope_bytes = match STANDARD.decode(&payload.envelope_b64) {
                Ok(bytes) => bytes,
                Err(_) => {
                    let _ = send_error(
                        out_tx,
                        frame.req_id,
                        "bad_payload",
                        "invalid base64 envelope",
                    )
                    .await;
                    return false;
                }
            };

            if envelope_bytes.len() > state.config.max_message_bytes {
                let _ = send_error(
                    out_tx,
                    frame.req_id,
                    "too_large",
                    "message exceeds max size",
                )
                .await;
                return false;
            }

            let (queued, depth) = state.queue.enqueue(
                payload.recipient_hash_hex.clone(),
                message_id,
                payload.envelope_b64.clone(),
            );

            let accepted_payload = MessageAcceptedPayload {
                message_id: payload.message_id.clone(),
                queued,
                queue_depth: depth,
            };
            let _ = send_frame(out_tx, "msg_accepted", frame.req_id, accepted_payload).await;

            let recipient_sender = state
                .sessions
                .get(&payload.recipient_hash_hex)
                .map(|recipient_session| recipient_session.sender.clone());

            if let Some(recipient_sender) = recipient_sender {
                let deliver_payload = MessageDeliverPayload {
                    message_id: payload.message_id,
                    envelope_b64: payload.envelope_b64,
                    queued_at_ms: Utc::now().timestamp_millis(),
                };
                if send_frame(&recipient_sender, "msg_deliver", None, deliver_payload)
                    .await
                    .is_ok()
                {
                    state
                        .queue
                        .dequeue_message(&payload.recipient_hash_hex, message_id);
                } else {
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
        "push_register" => {
            if *connection_role == ConnectionRole::Send {
                let _ = send_error(
                    out_tx,
                    frame.req_id,
                    "unauthorized",
                    "push_register not allowed on send connections",
                )
                .await;
                return false;
            }

            if state.push_tokens.len() >= state.config.max_push_registrations {
                let _ = send_error(
                    out_tx,
                    frame.req_id,
                    "server_busy",
                    "push registration limit reached",
                )
                .await;
                return false;
            }

            let Some(identity_hash) = authenticated_identity.as_ref() else {
                let _ = send_error(
                    out_tx,
                    frame.req_id,
                    "unauthorized",
                    "authenticate before registering push token",
                )
                .await;
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
                    )
                    .await;
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
                )
                .await;
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
                    registered_at: Instant::now(),
                },
            );
            info!(
                identity = %hash_prefix(identity_hash),
                apns_env = ?apns_env,
                has_topic_override,
                "registered APNS push token"
            );

            let _ = send_frame(out_tx, "push_registered", frame.req_id, EmptyPayload {}).await;
            false
        }
        "pong" => {
            *last_pong = Instant::now();
            false
        }
        "ping" => {
            let _ = send_frame(out_tx, "pong", frame.req_id, EmptyPayload {}).await;
            false
        }
        _ => {
            let _ = send_error(out_tx, frame.req_id, "bad_frame", "unsupported frame type").await;
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
    let state = state.clone();
    tokio::spawn(async move {
        info!(
            recipient = %hash_prefix(&recipient_hash),
            environment = ?request.environment,
            has_topic_override = request.topic_override.is_some(),
            "sending APNS push"
        );
        match apns_client.send_message_push(request).await {
            Ok(()) => {}
            Err(ApnsError::Rejected { status, .. }) if status == StatusCode::GONE => {
                state.push_tokens.remove(&recipient_hash);
                warn!(
                    recipient = %hash_prefix(&recipient_hash),
                    "removed expired APNS token (410 Gone)"
                );
            }
            Err(error) => {
                warn!(?error, "failed to send APNS message push");
            }
        }
    });
}

fn hash_prefix(value: &str) -> &str {
    let prefix_len = value.len().min(8);
    &value[..prefix_len]
}

async fn deliver_queued_messages(
    state: &Arc<RelayState>,
    recipient_hash: &str,
    sender: &mpsc::Sender<OutboundFrame>,
) -> Result<(), SendFrameError> {
    for queued in state.queue.messages_for_recipient(recipient_hash) {
        let payload = MessageDeliverPayload {
            message_id: queued.message_id.to_string(),
            envelope_b64: queued.envelope_b64,
            queued_at_ms: queued.queued_at.timestamp_millis(),
        };
        send_frame(sender, "msg_deliver", None, payload).await?;
        state
            .queue
            .dequeue_message(recipient_hash, queued.message_id);
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendFrameError {
    Serialize,
    QueueClosed,
    QueueFull,
    DeliveryFailed,
}

async fn send_frame<T>(
    tx: &mpsc::Sender<OutboundFrame>,
    frame_type: &'static str,
    req_id: Option<String>,
    payload: T,
) -> Result<(), SendFrameError>
where
    T: serde::Serialize,
{
    let serialized =
        frame_json(frame_type, req_id, payload).map_err(|_| SendFrameError::Serialize)?;
    let (outbound, delivery_rx) = OutboundFrame::with_confirmation(serialized);
    tx.try_send(outbound).map_err(|error| match error {
        tokio::sync::mpsc::error::TrySendError::Full(_) => SendFrameError::QueueFull,
        tokio::sync::mpsc::error::TrySendError::Closed(_) => SendFrameError::QueueClosed,
    })?;
    delivery_rx
        .await
        .map_err(|_| SendFrameError::DeliveryFailed)?
        .map_err(|_| SendFrameError::DeliveryFailed)
}

async fn send_error(
    tx: &mpsc::Sender<OutboundFrame>,
    req_id: Option<String>,
    code: &str,
    message: &str,
) -> Result<(), SendFrameError> {
    send_frame(
        tx,
        "error",
        req_id,
        ErrorPayload {
            code: code.to_string(),
            message: message.to_string(),
        },
    )
    .await
}

async fn purge_loop(state: Arc<RelayState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));

    loop {
        interval.tick().await;
        state.purge_expired();
        debug!(
            sessions = state.sessions.len(),
            challenges = state.challenges.len(),
            push_tokens = state.push_tokens.len(),
            "purged expired state"
        );
    }
}

fn is_valid_identity_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
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
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
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
        assert_eq!(deliver["payload"]["envelope_b64"], envelope_b64);

        server_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sealed_sender_deliver_payload_contains_no_sender_identity() {
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

        let _accepted = recv_json(&mut sender.socket).await;
        let deliver = recv_json(&mut recipient.socket).await;
        assert_eq!(deliver["type"], "msg_deliver");
        assert_eq!(deliver["payload"]["message_id"], message_id);
        assert_eq!(deliver["payload"]["envelope_b64"], envelope_b64);

        // Sealed sender: no sender identity in delivery payload
        assert!(deliver["payload"].get("sender_hash_hex").is_none());

        // Only expected fields present
        let payload_obj = deliver["payload"].as_object().unwrap();
        let keys: std::collections::HashSet<&str> =
            payload_obj.keys().map(|k| k.as_str()).collect();
        assert_eq!(
            keys,
            ["message_id", "envelope_b64", "queued_at_ms"]
                .into_iter()
                .collect()
        );

        server_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn anonymous_send_delivers_to_authenticated_recipient() {
        let (addr, server_task) = spawn_test_server(test_config(10)).await;

        let mut recipient = connect_authenticated_client(addr).await;

        let (mut sender_socket, _) = connect_async(format!("ws://{addr}/v1/ws"))
            .await
            .expect("connect sender");
        let message_id = Uuid::new_v4().to_string();
        let envelope_b64 = STANDARD.encode(b"sealed-envelope");

        send_json(
            &mut sender_socket,
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

        let accepted = recv_json(&mut sender_socket).await;
        assert_eq!(accepted["type"], "msg_accepted");

        let deliver = recv_json(&mut recipient.socket).await;
        assert_eq!(deliver["type"], "msg_deliver");
        assert_eq!(deliver["payload"]["envelope_b64"], envelope_b64);

        server_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn max_sized_message_is_accepted_by_websocket_transport() {
        let mut config = test_config(10);
        config.max_message_bytes = 16_384;
        let (addr, server_task) = spawn_test_server(config.clone()).await;

        let (mut sender_socket, _) = connect_async(format!("ws://{addr}/v1/ws"))
            .await
            .expect("connect sender");
        let envelope_b64 = STANDARD.encode(vec![0_u8; config.max_message_bytes]);

        send_json(
            &mut sender_socket,
            json!({
                "type": "msg_send",
                "payload": {
                    "message_id": Uuid::new_v4().to_string(),
                    "recipient_hash_hex": "a".repeat(64),
                    "envelope_b64": envelope_b64
                }
            }),
        )
        .await;

        let accepted = recv_json(&mut sender_socket).await;
        assert_eq!(accepted["type"], "msg_accepted");

        server_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn msg_send_rejected_on_receive_connection_when_legacy_off() {
        let mut config = test_config(10);
        config.allow_legacy_send = false;
        let (addr, server_task) = spawn_test_server(config).await;

        let mut client = connect_authenticated_client(addr).await;
        let message_id = Uuid::new_v4().to_string();
        let envelope_b64 = STANDARD.encode(b"opaque-envelope");

        send_json(
            &mut client.socket,
            json!({
                "type": "msg_send",
                "payload": {
                    "message_id": message_id,
                    "recipient_hash_hex": "a".repeat(64),
                    "envelope_b64": envelope_b64
                }
            }),
        )
        .await;

        let error = recv_json(&mut client.socket).await;
        assert_eq!(error["type"], "error");
        assert_eq!(error["payload"]["code"], "unauthorized");

        server_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn session_replacement_notifies_and_closes_old_connection() {
        let (addr, server_task) = spawn_test_server(test_config(10)).await;

        let mut client_secret_bytes = [0_u8; 32];
        rand::rng().fill_bytes(&mut client_secret_bytes);

        let mut original =
            connect_authenticated_client_with_secret(addr, client_secret_bytes).await;
        let replacement = connect_authenticated_client_with_secret(addr, client_secret_bytes).await;
        assert_eq!(original.identity_hash, replacement.identity_hash);

        let replaced = recv_json(&mut original.socket).await;
        assert_eq!(replaced["type"], "session_replaced");

        let close = original
            .socket
            .next()
            .await
            .expect("close frame")
            .expect("close message");

        match close {
            Message::Close(Some(frame)) => {
                assert_eq!(frame.code, CloseCode::Policy);
                assert_eq!(frame.reason, "session replaced");
            }
            other => panic!("expected close frame, got {other:?}"),
        }

        server_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn auth_hello_rejected_on_send_connection() {
        let (addr, server_task) = spawn_test_server(test_config(10)).await;

        let (mut socket, _) = connect_async(format!("ws://{addr}/v1/ws"))
            .await
            .expect("connect");

        send_json(
            &mut socket,
            json!({
                "type": "msg_send",
                "payload": {
                    "message_id": Uuid::new_v4().to_string(),
                    "recipient_hash_hex": "a".repeat(64),
                    "envelope_b64": STANDARD.encode(b"test")
                }
            }),
        )
        .await;
        let _ = recv_json(&mut socket).await;

        send_json(
            &mut socket,
            json!({
                "type": "auth_hello",
                "payload": {
                    "client_pubkey_b64": STANDARD.encode([0u8; 32])
                }
            }),
        )
        .await;

        let error = recv_json(&mut socket).await;
        assert_eq!(error["type"], "error");
        assert_eq!(error["payload"]["code"], "bad_frame");

        server_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn anonymous_send_connections_rate_limited_per_connection() {
        let (addr, server_task) = spawn_test_server(test_config(2)).await;

        let (mut socket_a, _) = connect_async(format!("ws://{addr}/v1/ws"))
            .await
            .expect("connect a");
        let (mut socket_b, _) = connect_async(format!("ws://{addr}/v1/ws"))
            .await
            .expect("connect b");

        for _ in 0..2 {
            send_json(
                &mut socket_a,
                json!({
                    "type": "msg_send",
                    "payload": {
                        "message_id": Uuid::new_v4().to_string(),
                        "recipient_hash_hex": "a".repeat(64),
                        "envelope_b64": STANDARD.encode(b"test")
                    }
                }),
            )
            .await;
            let _ = recv_json(&mut socket_a).await;
        }

        send_json(
            &mut socket_a,
            json!({
                "type": "msg_send",
                "payload": {
                    "message_id": Uuid::new_v4().to_string(),
                    "recipient_hash_hex": "a".repeat(64),
                    "envelope_b64": STANDARD.encode(b"test")
                }
            }),
        )
        .await;
        let rate_limited = recv_json(&mut socket_a).await;
        assert_eq!(rate_limited["type"], "error");
        assert_eq!(rate_limited["payload"]["code"], "rate_limited");

        send_json(
            &mut socket_b,
            json!({
                "type": "msg_send",
                "payload": {
                    "message_id": Uuid::new_v4().to_string(),
                    "recipient_hash_hex": "a".repeat(64),
                    "envelope_b64": STANDARD.encode(b"test")
                }
            }),
        )
        .await;
        let accepted = recv_json(&mut socket_b).await;
        assert_eq!(accepted["type"], "msg_accepted");

        server_task.abort();
    }

    fn spawn_confirming_writer(mut rx: mpsc::Receiver<OutboundFrame>) -> mpsc::Receiver<String> {
        let (captured_tx, captured_rx) = mpsc::channel(8);
        tokio::spawn(async move {
            while let Some(outbound) = rx.recv().await {
                let serialized = outbound.serialized.clone();
                if let Some(delivery_tx) = outbound.delivery_tx {
                    let _ = delivery_tx.send(Ok(()));
                }
                let _ = captured_tx.send(serialized).await;
            }
        });
        captured_rx
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_live_delivery_cleans_up_stale_session_and_keeps_message_queued() {
        let recipient_hash = "b".repeat(64);
        let sender_hash = "a".repeat(64);

        let state = Arc::new(RelayState::new(test_config(10), None));
        let (out_tx, out_rx) = mpsc::channel::<OutboundFrame>(4);
        let mut delivered_frames = spawn_confirming_writer(out_rx);
        let (dead_tx, dead_rx) = mpsc::channel::<OutboundFrame>(1);
        drop(dead_rx);

        state.register_session(recipient_hash.clone(), dead_tx, Duration::from_secs(60));

        let mut authenticated_identity = Some(sender_hash.clone());
        let mut rate_limit_key = sender_hash;
        let mut last_pong = Instant::now();
        let mut connection_role = ConnectionRole::Receive;
        let allow_legacy_send = true;

        let should_close = process_frame(
            &state,
            &out_tx,
            &mut authenticated_identity,
            &mut rate_limit_key,
            &mut last_pong,
            &mut connection_role,
            &allow_legacy_send,
            ClientFrame {
                frame_type: "msg_send".to_string(),
                req_id: Some("req-1".to_string()),
                payload: serde_json::json!({
                    "message_id": Uuid::new_v4().to_string(),
                    "recipient_hash_hex": recipient_hash,
                    "envelope_b64": STANDARD.encode(b"opaque-envelope"),
                }),
            },
        )
        .await;

        assert!(!should_close);
        assert!(state.sessions.get(&"b".repeat(64)).is_none());

        let accepted = delivered_frames.recv().await.expect("msg_accepted");
        let accepted: serde_json::Value =
            serde_json::from_str(&accepted).expect("parse msg_accepted");
        assert_eq!(accepted["type"], "msg_accepted");

        let queued = state.queue.messages_for_recipient(&"b".repeat(64));
        assert_eq!(queued.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn push_register_rejected_on_send_connection() {
        let (addr, server_task) = spawn_test_server(test_config(10)).await;

        let (mut socket, _) = connect_async(format!("ws://{addr}/v1/ws"))
            .await
            .expect("connect");

        // First frame is msg_send - assigns Send role
        send_json(
            &mut socket,
            json!({
                "type": "msg_send",
                "payload": {
                    "message_id": Uuid::new_v4().to_string(),
                    "recipient_hash_hex": "a".repeat(64),
                    "envelope_b64": STANDARD.encode(b"test")
                }
            }),
        )
        .await;
        let _ = recv_json(&mut socket).await;

        // Try push_register on a send connection
        send_json(
            &mut socket,
            json!({
                "type": "push_register",
                "payload": {
                    "device_token_hex": "aabb",
                    "apns_env": "sandbox"
                }
            }),
        )
        .await;

        let error = recv_json(&mut socket).await;
        assert_eq!(error["type"], "error");
        assert_eq!(error["payload"]["code"], "unauthorized");

        server_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unknown_first_frame_rejected() {
        let (addr, server_task) = spawn_test_server(test_config(10)).await;

        let (mut socket, _) = connect_async(format!("ws://{addr}/v1/ws"))
            .await
            .expect("connect");

        send_json(
            &mut socket,
            json!({
                "type": "push_register",
                "payload": {
                    "device_token_hex": "aabb",
                    "apns_env": "sandbox"
                }
            }),
        )
        .await;

        let error = recv_json(&mut socket).await;
        assert_eq!(error["type"], "error");
        assert_eq!(error["payload"]["code"], "bad_frame");

        server_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn msg_send_on_receive_connection_allowed_when_legacy_on() {
        let mut config = test_config(10);
        config.allow_legacy_send = true;
        let (addr, server_task) = spawn_test_server(config).await;

        let mut client = connect_authenticated_client(addr).await;
        let message_id = Uuid::new_v4().to_string();
        let envelope_b64 = STANDARD.encode(b"legacy-send-test");

        send_json(
            &mut client.socket,
            json!({
                "type": "msg_send",
                "payload": {
                    "message_id": message_id,
                    "recipient_hash_hex": "a".repeat(64),
                    "envelope_b64": envelope_b64
                }
            }),
        )
        .await;

        let accepted = recv_json(&mut client.socket).await;
        assert_eq!(accepted["type"], "msg_accepted");

        server_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_recipient_send_queue_keeps_message_queued() {
        let recipient_hash = "b".repeat(64);
        let sender_hash = "a".repeat(64);

        let state = Arc::new(RelayState::new(test_config(10), None));
        let (out_tx, out_rx) = mpsc::channel::<OutboundFrame>(4);
        let _delivered_frames = spawn_confirming_writer(out_rx);
        let (recipient_tx, _recipient_rx) = mpsc::channel::<OutboundFrame>(1);

        recipient_tx
            .try_send(OutboundFrame::fire_and_forget(
                r#"{"type":"filler","payload":{}}"#.to_string(),
            ))
            .expect("fill recipient outbound queue");

        state.register_session(
            recipient_hash.clone(),
            recipient_tx,
            Duration::from_secs(60),
        );

        let mut authenticated_identity = Some(sender_hash.clone());
        let mut rate_limit_key = sender_hash;
        let mut last_pong = Instant::now();
        let mut connection_role = ConnectionRole::Receive;
        let allow_legacy_send = true;
        let message_id = Uuid::new_v4();

        let should_close = process_frame(
            &state,
            &out_tx,
            &mut authenticated_identity,
            &mut rate_limit_key,
            &mut last_pong,
            &mut connection_role,
            &allow_legacy_send,
            ClientFrame {
                frame_type: "msg_send".to_string(),
                req_id: Some("req-queue-full".to_string()),
                payload: serde_json::json!({
                    "message_id": message_id.to_string(),
                    "recipient_hash_hex": recipient_hash,
                    "envelope_b64": STANDARD.encode(b"opaque-envelope"),
                }),
            },
        )
        .await;

        assert!(!should_close);
        assert!(state.sessions.get(&"b".repeat(64)).is_none());

        let queued = state.queue.messages_for_recipient(&"b".repeat(64));
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].message_id, message_id);
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

    async fn connect_authenticated_client(addr: SocketAddr) -> AuthenticatedClient {
        let mut client_secret_bytes = [0_u8; 32];
        rand::rng().fill_bytes(&mut client_secret_bytes);
        connect_authenticated_client_with_secret(addr, client_secret_bytes).await
    }

    async fn connect_authenticated_client_with_secret(
        addr: SocketAddr,
        client_secret_bytes: [u8; 32],
    ) -> AuthenticatedClient {
        let url = format!("ws://{addr}/v1/ws");
        let (mut socket, _) = connect_async(url).await.expect("connect websocket");

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
            max_session_send_queue: 128,
            challenge_ttl: Duration::from_secs(30),
            session_ttl: Duration::from_secs(3600),
            rate_limit_per_min,
            ping_interval: Duration::from_secs(300),
            pong_timeout: Duration::from_secs(600),
            max_concurrent_challenges: 10_000,
            max_push_registrations: 10_000,
            push_token_ttl: Duration::from_secs(3600),
            allow_legacy_send: true,
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
