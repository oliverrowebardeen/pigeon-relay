use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct QueuedMessage {
    pub message_id: Uuid,
    #[allow(dead_code)]
    pub recipient_hash: String,
    pub envelope_b64: String,
    pub queued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Default)]
struct RecipientQueue {
    messages: VecDeque<QueuedMessage>,
    dedup: HashMap<Uuid, DateTime<Utc>>,
}

#[derive(Debug)]
pub struct QueueStore {
    message_ttl: Duration,
    max_queue_per_recipient: usize,
    queues: DashMap<String, RecipientQueue>,
}

impl QueueStore {
    pub fn new(message_ttl: Duration, max_queue_per_recipient: usize) -> Self {
        Self {
            message_ttl,
            max_queue_per_recipient,
            queues: DashMap::new(),
        }
    }

    pub fn enqueue(
        &self,
        recipient_hash: String,
        message_id: Uuid,
        envelope_b64: String,
    ) -> (bool, usize) {
        let now = Utc::now();
        let mut recipient_queue = self.queues.entry(recipient_hash.clone()).or_default();

        if let Some(existing_expiry) = recipient_queue.dedup.get(&message_id)
            && *existing_expiry > now
        {
            return (false, recipient_queue.messages.len());
        }

        let expires_at = now
            + chrono::Duration::from_std(self.message_ttl).unwrap_or(chrono::Duration::hours(24));

        let entry = QueuedMessage {
            message_id,
            recipient_hash,
            envelope_b64,
            queued_at: now,
            expires_at,
        };

        recipient_queue.messages.push_back(entry);
        recipient_queue.dedup.insert(message_id, expires_at);

        while recipient_queue.messages.len() > self.max_queue_per_recipient {
            if let Some(dropped) = recipient_queue.messages.pop_front() {
                recipient_queue.dedup.remove(&dropped.message_id);
            }
        }

        (true, recipient_queue.messages.len())
    }

    pub fn messages_for_recipient(&self, recipient_hash: &str) -> Vec<QueuedMessage> {
        let now = Utc::now();

        self.queues
            .get(recipient_hash)
            .map(|recipient_queue| {
                recipient_queue
                    .messages
                    .iter()
                    .filter(|message| message.expires_at > now)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn dequeue_message(&self, recipient_hash: &str, message_id: Uuid) -> bool {
        let mut removed = false;

        if let Some(mut recipient_queue) = self.queues.get_mut(recipient_hash)
            && let Some(index) = recipient_queue
                .messages
                .iter()
                .position(|item| item.message_id == message_id)
        {
            recipient_queue.messages.remove(index);
            recipient_queue.dedup.remove(&message_id);
            removed = true;
        }

        removed
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn depth_for(&self, recipient_hash: &str) -> usize {
        self.queues
            .get(recipient_hash)
            .map_or(0, |recipient_queue| recipient_queue.messages.len())
    }

    pub fn purge_expired(&self) {
        let now = Utc::now();

        self.queues.retain(|_, recipient_queue| {
            recipient_queue
                .dedup
                .retain(|_, expires_at| *expires_at > now);
            recipient_queue
                .messages
                .retain(|message| message.expires_at > now);
            !recipient_queue.messages.is_empty() || !recipient_queue.dedup.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    #[test]
    fn dedup_prevents_duplicate_enqueue() {
        let queue = QueueStore::new(Duration::from_secs(3600), 100);
        let recipient = "abcd".to_string();
        let id = Uuid::new_v4();

        let first = queue.enqueue(recipient.clone(), id, "blob".to_string());
        let second = queue.enqueue(recipient.clone(), id, "blob".to_string());

        assert!(first.0);
        assert!(!second.0);
        assert_eq!(queue.depth_for(&recipient), 1);
    }

    #[test]
    fn concurrent_enqueue_dedup_is_atomic() {
        const THREADS: usize = 32;

        let queue = Arc::new(QueueStore::new(Duration::from_secs(3600), 100));
        let recipient = Arc::new("abcd".to_string());
        let id = Uuid::new_v4();
        let barrier = Arc::new(Barrier::new(THREADS));

        let results = thread::scope(|scope| {
            let mut handles = Vec::with_capacity(THREADS);

            for _ in 0..THREADS {
                let queue = Arc::clone(&queue);
                let recipient = Arc::clone(&recipient);
                let barrier = Arc::clone(&barrier);

                handles.push(scope.spawn(move || {
                    barrier.wait();
                    queue.enqueue((*recipient).clone(), id, "blob".to_string())
                }));
            }

            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });

        assert_eq!(
            results
                .iter()
                .filter(|&&(queued, depth)| queued && depth == 1)
                .count(),
            1
        );
        assert_eq!(results.iter().filter(|&&(queued, _)| queued).count(), 1);

        let queued = queue.messages_for_recipient(&recipient);
        assert_eq!(queued.len(), 1);
        assert_eq!(queue.depth_for(&recipient), 1);
        assert_eq!(queued[0].message_id, id);
        assert_eq!(queued[0].recipient_hash.as_str(), recipient.as_str());
    }
}
