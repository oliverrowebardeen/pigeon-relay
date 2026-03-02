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
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/ws", get(ws_handler))
        .with_state(state.clone());

    tokio::spawn(purge_loop(state.clone()));

    let listener = TcpListener::bind(&state.config.relay_addr).await?;
    info!(addr = %state.config.relay_addr, "relay server listening");
    axum::serve(listener, app).await?;
    Ok(())
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
    let mut ping_interval = tokio::time::interval(state.config.ping_interval);

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
            let padding = payload.envelope_b64.as_bytes().iter().rev().take_while(|&&b| b == b'=').count();
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
                let _ = send_frame(
                    &recipient_session.sender,
                    "msg_deliver",
                    None,
                    deliver_payload,
                );
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
                    let _ = send_frame(
                        &sender_session.sender,
                        "msg_acked",
                        None,
                        ack_payload.clone(),
                    );
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

            state.push_tokens.insert(
                identity_hash.clone(),
                PushRegistration {
                    device_token_hex: payload.device_token_hex,
                    apns_env,
                    topic_override: payload.topic,
                    last_push_at: None,
                },
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
    tokio::spawn(async move {
        if let Err(error) = apns_client.send_silent_push(request).await {
            warn!(?error, "failed to send APNS silent push");
        }
    });
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
