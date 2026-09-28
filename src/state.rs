use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::close_code;
use chrono::Utc;
use dashmap::DashMap;
use tokio::sync::{Semaphore, mpsc, oneshot};
use uuid::Uuid;

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
    pub(crate) token: Uuid,
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
    pub connection_slots: Arc<Semaphore>,
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
            connection_slots: Arc::new(Semaphore::new(config.max_connections)),
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
    ) -> Uuid {
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
        let token = Uuid::new_v4();
        let handle = SessionHandle {
            sender,
            expires_at: now + session_ttl,
            token,
        };
        self.sessions.insert(identity_hash, handle);
        token
    }

    pub fn unregister_session(&self, identity_hash: &str, token: Uuid) {
        self.sessions
            .remove_if(identity_hash, |_, session| session.token == token);
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

    pub fn purge_expired_challenges(&self) {
        let now = Utc::now();
        self.challenges
            .retain(|_, challenge| challenge.expires_at > now);
    }

    pub fn purge_expired(&self) {
        let now = Instant::now();

        self.purge_expired_challenges();
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
    use crate::config::ApnsConfig;

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

    #[test]
    fn old_session_exit_does_not_evict_replacement() {
        let state = RelayState::new(test_config(), None);
        let identity_hash = "a".repeat(64);
        let (sender_a, _receiver_a) = mpsc::channel(1);
        let (sender_b, _receiver_b) = mpsc::channel(1);

        let token_a =
            state.register_session(identity_hash.clone(), sender_a, Duration::from_secs(60));
        let token_b =
            state.register_session(identity_hash.clone(), sender_b, Duration::from_secs(60));

        state.unregister_session(&identity_hash, token_a);

        let session = state
            .sessions
            .get(&identity_hash)
            .expect("replacement session should remain registered");
        assert_eq!(session.token, token_b);
    }

    fn test_config() -> Config {
        Config {
            relay_addr: "127.0.0.1:0".to_string(),
            max_connections: 1024,
            message_ttl: Duration::from_secs(3600),
            max_message_bytes: 65_536,
            max_queue_per_recipient: 500,
            max_session_send_queue: 128,
            challenge_ttl: Duration::from_secs(30),
            session_ttl: Duration::from_secs(3600),
            rate_limit_per_min: 10,
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
