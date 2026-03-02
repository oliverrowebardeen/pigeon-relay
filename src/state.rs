use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use dashmap::DashMap;
use tokio::sync::mpsc;

use crate::apns::ApnsClient;
use crate::auth::ChallengeRecord;
use crate::config::{ApnsEnvironment, Config};
use crate::protocol::MessageAckedPayload;
use crate::queue::QueueStore;

#[derive(Debug, Clone)]
pub struct SessionHandle {
    pub sender: mpsc::UnboundedSender<String>,
    pub expires_at: Instant,
}

#[derive(Debug, Clone)]
pub struct PushRegistration {
    pub device_token_hex: String,
    pub apns_env: ApnsEnvironment,
    pub topic_override: Option<String>,
    pub last_push_at: Option<Instant>,
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
    pub pending_acks: DashMap<String, (Instant, VecDeque<MessageAckedPayload>)>,
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
            pending_acks: DashMap::new(),
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
        sender: mpsc::UnboundedSender<String>,
        session_ttl: Duration,
    ) {
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

    pub fn store_pending_ack(&self, sender_hash: &str, payload: MessageAckedPayload) {
        let now = Instant::now();
        let mut entry = self
            .pending_acks
            .entry(sender_hash.to_string())
            .or_insert_with(|| (now, VecDeque::new()));
        entry.0 = now;
        entry.1.push_back(payload);
    }

    pub fn take_pending_acks(&self, sender_hash: &str) -> Vec<MessageAckedPayload> {
        if let Some((_, (_, pending))) = self.pending_acks.remove(sender_hash) {
            return pending.into_iter().collect();
        }
        Vec::new()
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
        self.pending_acks
            .retain(|_, (stored_at, _)| now.duration_since(*stored_at) <= self.config.session_ttl);

        self.queue.purge_expired();
    }
}
