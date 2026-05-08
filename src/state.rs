use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::close_code;
use chrono::Utc;
use dashmap::DashMap;
use tokio::sync::{mpsc, oneshot};

use crate::apns::ApnsClient;
use crate::auth::ChallengeRecord;
use crate::config::{ApnsEnvironment, Config};
use crate::queue::QueueStore;

#[derive(Debug)]
pub struct OutboundFrame {
    pub serialized: String,
    pub delivery_tx: Option<oneshot::Sender<Result<(), ()>>>,
    pub close_after_send: Option<CloseDirective>,
}

#[derive(Debug)]
pub struct CloseDirective {
    pub code: u16,
    pub reason: String,
}

impl OutboundFrame {
    #[cfg(test)]
    pub fn fire_and_forget(serialized: String) -> Self {
        Self {
            serialized,
            delivery_tx: None,
            close_after_send: None,
        }
    }

    pub fn with_confirmation(serialized: String) -> (Self, oneshot::Receiver<Result<(), ()>>) {
        let (delivery_tx, delivery_rx) = oneshot::channel();
        (
            Self {
                serialized,
                delivery_tx: Some(delivery_tx),
                close_after_send: None,
            },
            delivery_rx,
        )
    }

    pub fn fire_and_forget_and_close(
        serialized: String,
        code: u16,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            serialized,
            delivery_tx: None,
            close_after_send: Some(CloseDirective {
                code,
                reason: reason.into(),
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionHandle {
    pub sender: mpsc::Sender<OutboundFrame>,
    pub expires_at: Instant,
}

#[derive(Clone)]
pub struct PushRegistration {
    pub device_token_hex: String,
    pub apns_env: ApnsEnvironment,
    pub topic_override: Option<String>,
    pub last_push_at: Option<Instant>,
    pub registered_at: Instant,
}

impl std::fmt::Debug for PushRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushRegistration")
            .field("device_token_hex", &"<redacted>")
            .field("apns_env", &self.apns_env)
            .field("topic_override", &self.topic_override)
            .field("last_push_at", &self.last_push_at)
            .field("registered_at", &self.registered_at)
            .finish()
    }
}

#[derive(Debug)]
struct RateLimitWindow {
    started_at: Instant,
    count: u32,
}

#[derive(Debug)]
pub struct RelayState {
    pub config: Config,
    pub queue: QueueStore,
    pub sessions: DashMap<String, SessionHandle>,
    pub challenges: DashMap<String, ChallengeRecord>,
    pub push_tokens: DashMap<String, PushRegistration>,
    rate_limits: DashMap<String, RateLimitWindow>,
    pub apns_client: Option<Arc<ApnsClient>>,
}

impl RelayState {
    pub fn new(config: Config, apns_client: Option<Arc<ApnsClient>>) -> Self {
        let queue = QueueStore::new(config.message_ttl, config.max_queue_per_recipient);

        Self {
            config,
            queue,
            sessions: DashMap::new(),
            challenges: DashMap::new(),
            push_tokens: DashMap::new(),
            rate_limits: DashMap::new(),
            apns_client,
        }
    }

    pub fn allow_request(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut window = self
            .rate_limits
            .entry(key.to_string())
            .or_insert(RateLimitWindow {
                started_at: now,
                count: 0,
            });

        if now.duration_since(window.started_at) > Duration::from_secs(60) {
            window.started_at = now;
            window.count = 0;
        }

        if window.count >= self.config.rate_limit_per_min {
            return false;
        }

        window.count += 1;
        true
    }

    pub fn register_session(
        &self,
        identity_hash: String,
        sender: mpsc::Sender<OutboundFrame>,
        session_ttl: Duration,
    ) {
        // Notify old session before replacing it (I2: session hijacking prevention)
        if let Some((_, old_handle)) = self.sessions.remove(&identity_hash) {
            let _ = old_handle
                .sender
                .try_send(OutboundFrame::fire_and_forget_and_close(
                    r#"{"type":"session_replaced","payload":{}}"#.to_string(),
                    close_code::POLICY,
                    "session replaced",
                ));
        }

        let now = Instant::now();
        let handle = SessionHandle {
            sender,
            expires_at: now + session_ttl,
        };
        self.sessions.insert(identity_hash, handle);
    }

    pub fn unregister_session(&self, identity_hash: &str) {
        self.sessions.remove(identity_hash);
    }

    pub fn maybe_record_push(&self, recipient_hash: &str, cooldown: Duration) -> bool {
        let Some(mut push) = self.push_tokens.get_mut(recipient_hash) else {
            return false;
        };

        let now = Instant::now();
        if let Some(last_push_at) = push.last_push_at
            && now.duration_since(last_push_at) < cooldown
        {
            return false;
        }

        push.last_push_at = Some(now);
        true
    }

    pub fn purge_expired(&self) {
        let now = Instant::now();
        let now_chrono = Utc::now();

        self.challenges
            .retain(|_, challenge| challenge.expires_at > now_chrono);
        self.sessions.retain(|_, session| session.expires_at > now);
        self.rate_limits
            .retain(|_, window| now.duration_since(window.started_at) <= Duration::from_secs(300));
        self.push_tokens
            .retain(|_, reg| now.duration_since(reg.registered_at) <= self.config.push_token_ttl);

        self.queue.purge_expired();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_registration_debug_redacts_device_token() {
        let token = "deadbeef".repeat(8);
        let registration = PushRegistration {
            device_token_hex: token.clone(),
            apns_env: ApnsEnvironment::Sandbox,
            topic_override: Some("com.example.pigeon".to_string()),
            last_push_at: None,
            registered_at: Instant::now(),
        };

        let formatted = format!("{registration:?}");
        assert!(
            !formatted.contains(&token),
            "device token leaked into Debug output: {formatted}"
        );
        assert!(formatted.contains("<redacted>"));
        assert!(formatted.contains("Sandbox"));
    }
}
