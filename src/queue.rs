use std::collections::VecDeque;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct QueuedMessage {
    pub message_id: Uuid,
    pub sender_hash: String,
    pub recipient_hash: String,
    pub envelope_b64: String,
    pub queued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct QueueStore {
    message_ttl: Duration,
    max_queue_per_recipient: usize,
    queues: DashMap<String, VecDeque<QueuedMessage>>,
    dedup: DashMap<String, DateTime<Utc>>,
}

impl QueueStore {
    pub fn new(message_ttl: Duration, max_queue_per_recipient: usize) -> Self {
        Self {
            message_ttl,
            max_queue_per_recipient,
            queues: DashMap::new(),
            dedup: DashMap::new(),
        }
    }

    pub fn enqueue(
        &self,
        sender_hash: String,
        recipient_hash: String,
        message_id: Uuid,
        envelope_b64: String,
    ) -> (bool, usize) {
        let now = Utc::now();
        let dedup_key = Self::dedup_key(&recipient_hash, message_id);

        if let Some(existing_expiry) = self.dedup.get(&dedup_key)
            && *existing_expiry > now
        {
            let depth = self.depth_for(&recipient_hash);
            return (false, depth);
        }

        let expires_at = now
            + chrono::Duration::from_std(self.message_ttl).unwrap_or(chrono::Duration::hours(24));

        let entry = QueuedMessage {
            message_id,
            sender_hash,
            recipient_hash: recipient_hash.clone(),
            envelope_b64,
            queued_at: now,
            expires_at,
        };

        let mut queue = self.queues.entry(recipient_hash).or_default();
        queue.push_back(entry);

        while queue.len() > self.max_queue_per_recipient {
            if let Some(dropped) = queue.pop_front() {
                self.dedup.remove(&Self::dedup_key(
                    &dropped.recipient_hash,
                    dropped.message_id,
                ));
            }
        }

        self.dedup.insert(dedup_key, expires_at);

        (true, queue.len())
    }

    pub fn drain_for_recipient(&self, recipient_hash: &str) -> Vec<QueuedMessage> {
        let now = Utc::now();

        if let Some(mut queue) = self.queues.get_mut(recipient_hash) {
            let drained: Vec<QueuedMessage> = queue
                .drain(..)
                .filter(|message| message.expires_at > now)
                .collect();
            for msg in &drained {
                self.dedup
                    .remove(&Self::dedup_key(recipient_hash, msg.message_id));
            }
            return drained;
        }

        Vec::new()
    }

    pub fn ack_message(&self, recipient_hash: &str, message_id: Uuid) -> Option<QueuedMessage> {
        let mut removed = None;

        if let Some(mut queue) = self.queues.get_mut(recipient_hash)
            && let Some(index) = queue.iter().position(|item| item.message_id == message_id)
        {
            removed = queue.remove(index);
        }

        self.dedup
            .remove(&Self::dedup_key(recipient_hash, message_id));

        removed
    }

    pub fn depth_for(&self, recipient_hash: &str) -> usize {
        self.queues
            .get(recipient_hash)
            .map_or(0, |queue| queue.len())
    }

    pub fn purge_expired(&self) {
        let now = Utc::now();

        self.dedup.retain(|_, expires_at| *expires_at > now);

        self.queues.retain(|_, queue| {
            queue.retain(|message| message.expires_at > now);
            !queue.is_empty()
        });
    }

    fn dedup_key(recipient_hash: &str, message_id: Uuid) -> String {
        format!("{recipient_hash}:{message_id}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_prevents_duplicate_enqueue() {
        let queue = QueueStore::new(Duration::from_secs(3600), 100);
        let recipient = "abcd".to_string();
        let sender = "efgh".to_string();
        let id = Uuid::new_v4();

        let first = queue.enqueue(sender.clone(), recipient.clone(), id, "blob".to_string());
        let second = queue.enqueue(sender, recipient.clone(), id, "blob".to_string());

        assert!(first.0);
        assert!(!second.0);
        assert_eq!(queue.depth_for(&recipient), 1);
    }
}
