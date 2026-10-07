use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct QueuedMessage {
    pub message_id: Uuid,
    pub recipient_hash: String,
    pub envelope_b64: String,
    pub queued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl QueuedMessage {
    fn queued_bytes(&self) -> usize {
        // Charge stored strings plus message, dedup, and recipient bookkeeping.
        // Charging recipient overhead per message also bounds empty envelopes.
        // Allocator/container spare capacity is not an exact process RSS budget.
        self.envelope_b64
            .capacity()
            .saturating_add(self.recipient_hash.capacity())
            .saturating_add(self.recipient_hash.len())
            .saturating_add(std::mem::size_of::<Self>())
            .saturating_add(std::mem::size_of::<(Uuid, DateTime<Utc>)>())
            .saturating_add(std::mem::size_of::<(String, RecipientQueue)>())
    }
}

#[derive(Debug, Default)]
struct RecipientQueue {
    messages: VecDeque<QueuedMessage>,
    dedup: HashMap<Uuid, DateTime<Utc>>,
    queued_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueFull;

#[derive(Debug)]
pub struct QueueStore {
    message_ttl: Duration,
    max_queue_per_recipient: usize,
    max_total_queued_bytes: usize,
    total_queued_bytes: AtomicUsize,
    queues: DashMap<String, RecipientQueue>,
}

impl QueueStore {
    pub fn new(
        message_ttl: Duration,
        max_queue_per_recipient: usize,
        max_total_queued_bytes: usize,
    ) -> Self {
        Self {
            message_ttl,
            max_queue_per_recipient,
            max_total_queued_bytes,
            total_queued_bytes: AtomicUsize::new(0),
            queues: DashMap::new(),
        }
    }

    pub fn enqueue(
        &self,
        recipient_hash: String,
        message_id: Uuid,
        envelope_b64: String,
    ) -> Result<(bool, usize), QueueFull> {
        let now = Utc::now();
        let expires_at = now
            + chrono::Duration::from_std(self.message_ttl).unwrap_or(chrono::Duration::hours(24));
        self.insert_message(QueuedMessage {
            message_id,
            recipient_hash,
            envelope_b64,
            queued_at: now,
            expires_at,
        })
    }

    fn insert_message(&self, message: QueuedMessage) -> Result<(bool, usize), QueueFull> {
        match self.queues.entry(message.recipient_hash.clone()) {
            Entry::Occupied(mut entry) => {
                let result = self.insert_into_queue(entry.get_mut(), message);
                if entry.get().messages.is_empty() {
                    entry.remove();
                }
                result
            }
            Entry::Vacant(entry) => {
                let mut queue = RecipientQueue::default();
                let result = self.insert_into_queue(&mut queue, message)?;
                entry.insert(queue);
                Ok(result)
            }
        }
    }

    fn insert_into_queue(
        &self,
        queue: &mut RecipientQueue,
        message: QueuedMessage,
    ) -> Result<(bool, usize), QueueFull> {
        self.purge_recipient(queue, Utc::now());
        if queue.dedup.contains_key(&message.message_id) {
            return Ok((false, queue.messages.len()));
        }
        if queue.messages.len() >= self.max_queue_per_recipient {
            return Err(QueueFull);
        }

        let bytes = message.queued_bytes();
        // Reserve atomically across shards before adding to any recipient queue.
        self.total_queued_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |total| {
                total
                    .checked_add(bytes)
                    .filter(|next| *next <= self.max_total_queued_bytes)
            })
            .map_err(|_| QueueFull)?;
        queue.queued_bytes += bytes;
        queue.dedup.insert(message.message_id, message.expires_at);
        queue.messages.push_back(message);
        Ok((true, queue.messages.len()))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn messages_for_recipient(&self, recipient_hash: &str) -> Vec<QueuedMessage> {
        let now = Utc::now();
        self.queues
            .get(recipient_hash)
            .map(|queue| {
                queue
                    .messages
                    .iter()
                    .filter(|message| message.expires_at > now)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn take_all_for_recipient(&self, recipient_hash: &str) -> Vec<QueuedMessage> {
        let Some((_, queue)) = self.queues.remove(recipient_hash) else {
            return Vec::new();
        };
        self.total_queued_bytes
            .fetch_sub(queue.queued_bytes, Ordering::Relaxed);
        let now = Utc::now();
        queue
            .messages
            .into_iter()
            .filter(|message| message.expires_at > now)
            .collect()
    }

    // A drain releases its reservation. Concurrent sends may consume that space,
    // so failed deliveries must reserve capacity again and can be dropped.
    pub fn requeue_messages(&self, messages: Vec<QueuedMessage>) -> usize {
        let mut dropped = 0;
        for message in messages {
            if message.expires_at > Utc::now() && self.insert_message(message).is_err() {
                dropped += 1;
            }
        }
        dropped
    }

    pub fn dequeue_message(&self, recipient_hash: &str, message_id: Uuid) -> bool {
        let Entry::Occupied(mut entry) = self.queues.entry(recipient_hash.to_string()) else {
            return false;
        };
        let queue = entry.get_mut();
        let Some(index) = queue
            .messages
            .iter()
            .position(|item| item.message_id == message_id)
        else {
            return false;
        };
        let message = queue.messages.remove(index).expect("message index exists");
        let bytes = message.queued_bytes();
        queue.dedup.remove(&message_id);
        queue.queued_bytes -= bytes;
        self.total_queued_bytes.fetch_sub(bytes, Ordering::Relaxed);
        if queue.messages.is_empty() {
            entry.remove();
        }
        true
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn depth_for(&self, recipient_hash: &str) -> usize {
        self.queues
            .get(recipient_hash)
            .map_or(0, |queue| queue.messages.len())
    }

    fn purge_recipient(&self, queue: &mut RecipientQueue, now: DateTime<Utc>) {
        let mut released = 0;
        queue.messages.retain(|message| {
            if message.expires_at <= now {
                released += message.queued_bytes();
                queue.dedup.remove(&message.message_id);
                false
            } else {
                true
            }
        });
        queue.queued_bytes -= released;
        self.total_queued_bytes
            .fetch_sub(released, Ordering::Relaxed);
    }

    pub fn purge_expired(&self) {
        let now = Utc::now();
        self.queues.retain(|_, queue| {
            self.purge_recipient(queue, now);
            !queue.messages.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn message_cost(recipient: &str, envelope: &str) -> usize {
        QueuedMessage {
            message_id: Uuid::new_v4(),
            recipient_hash: recipient.to_string(),
            envelope_b64: envelope.to_string(),
            queued_at: Utc::now(),
            expires_at: Utc::now(),
        }
        .queued_bytes()
    }

    fn total_bytes(queue: &QueueStore) -> usize {
        queue.total_queued_bytes.load(Ordering::Relaxed)
    }

    #[test]
    fn global_cap_rejects_across_recipients_and_releases_after_dequeue_and_drain() {
        let bytes = message_cost("aaaa", "blob");
        let queue = QueueStore::new(Duration::from_secs(3600), 100, 2 * bytes);
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert_eq!(
            queue.enqueue("aaaa".into(), a, "blob".into()),
            Ok((true, 1))
        );
        assert_eq!(
            queue.enqueue("bbbb".into(), b, "blob".into()),
            Ok((true, 1))
        );
        assert_eq!(total_bytes(&queue), 2 * bytes);
        assert_eq!(
            queue.enqueue("cccc".into(), Uuid::new_v4(), "blob".into()),
            Err(QueueFull)
        );
        assert_eq!(
            queue.queues.len(),
            2,
            "rejection must not leave an empty recipient queue"
        );
        assert_eq!(
            queue.enqueue("aaaa".into(), a, "blob".into()),
            Ok((false, 1))
        );
        assert_eq!(
            total_bytes(&queue),
            2 * bytes,
            "dedup must not reserve twice"
        );
        assert!(!queue.dequeue_message("aaaa", Uuid::new_v4()));
        assert!(queue.dequeue_message("aaaa", a));
        assert!(!queue.dequeue_message("aaaa", a));
        assert_eq!(total_bytes(&queue), bytes);
        assert!(!queue.queues.contains_key("aaaa"));
        let c = Uuid::new_v4();
        queue.enqueue("cccc".into(), c, "blob".into()).unwrap();
        let drained = queue.take_all_for_recipient("bbbb");
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].message_id, b);
        assert_eq!(total_bytes(&queue), bytes);
        assert_eq!(queue.requeue_messages(drained.clone()), 0);
        assert_eq!(
            queue.requeue_messages(drained),
            0,
            "duplicate requeue is ignored"
        );
        assert_eq!(total_bytes(&queue), 2 * bytes);
        queue.take_all_for_recipient("bbbb");
        queue.take_all_for_recipient("cccc");
        assert_eq!(total_bytes(&queue), 0);
        assert!(queue.queues.is_empty());
    }

    #[test]
    fn per_recipient_overflow_rejects_without_evicting_accepted_message() {
        let queue = QueueStore::new(Duration::from_secs(3600), 1, 1024 * 1024);
        let id = Uuid::new_v4();
        queue.enqueue("aaaa".into(), id, "blob".into()).unwrap();
        let bytes = total_bytes(&queue);
        assert_eq!(
            queue.enqueue("aaaa".into(), Uuid::new_v4(), "blob".into()),
            Err(QueueFull)
        );
        assert_eq!(total_bytes(&queue), bytes);
        assert_eq!(queue.take_all_for_recipient("aaaa")[0].message_id, id);
        assert_eq!(total_bytes(&queue), 0);
    }

    #[test]
    fn expiry_releases_bytes_on_purge_drain_and_enqueue() {
        for removal in ["purge", "drain", "enqueue"] {
            let bytes = message_cost("aaaa", "blob");
            let queue = QueueStore::new(Duration::from_secs(3600), 1, bytes);
            let id = Uuid::new_v4();
            queue.enqueue("aaaa".into(), id, "blob".into()).unwrap();
            // Advance the message's deadline without sleeping or depending on clock resolution.
            queue.queues.get_mut("aaaa").unwrap().messages[0].expires_at =
                Utc::now() - chrono::Duration::seconds(1);
            match removal {
                "purge" => queue.purge_expired(),
                "drain" => assert!(queue.take_all_for_recipient("aaaa").is_empty()),
                _ => {
                    // Reusing the ID also verifies that expiry removes the dedup entry.
                    assert_eq!(
                        queue.enqueue("aaaa".into(), id, "blob".into()),
                        Ok((true, 1))
                    );
                    queue.dequeue_message("aaaa", id);
                }
            }
            assert_eq!(total_bytes(&queue), 0);
            assert!(queue.queues.is_empty());
            assert!(
                queue
                    .enqueue("bbbb".into(), Uuid::new_v4(), "blob".into())
                    .is_ok()
            );
        }
    }

    #[test]
    fn failed_delivery_requeue_cannot_exceed_cap_or_revive_expired_messages() {
        let bytes = message_cost("aaaa", "blob");
        let queue = QueueStore::new(Duration::from_secs(3600), 100, bytes);
        queue
            .enqueue("aaaa".into(), Uuid::new_v4(), "blob".into())
            .unwrap();
        let mut drained = queue.take_all_for_recipient("aaaa");
        queue
            .enqueue("bbbb".into(), Uuid::new_v4(), "blob".into())
            .unwrap();
        assert_eq!(queue.requeue_messages(drained.clone()), 1);
        assert_eq!(total_bytes(&queue), bytes);
        assert!(!queue.queues.contains_key("aaaa"));
        queue.take_all_for_recipient("bbbb");
        drained[0].expires_at = Utc::now() - chrono::Duration::seconds(1);
        assert_eq!(queue.requeue_messages(drained), 0);
        assert_eq!(total_bytes(&queue), 0);
        assert!(queue.queues.is_empty());
    }

    #[test]
    fn empty_envelopes_still_consume_global_capacity() {
        let bytes = message_cost("aaaa", "");
        assert!(bytes > 0);
        let queue = QueueStore::new(Duration::from_secs(3600), 100, bytes);
        queue
            .enqueue("aaaa".into(), Uuid::new_v4(), String::new())
            .unwrap();
        assert_eq!(
            queue.enqueue("bbbb".into(), Uuid::new_v4(), String::new()),
            Err(QueueFull)
        );
        assert_eq!(total_bytes(&queue), bytes);
        assert_eq!(queue.queues.len(), 1);
    }

    #[test]
    fn concurrent_recipients_cannot_overcommit_global_cap() {
        const THREADS: usize = 32;
        let bytes = message_cost("0000", "blob");
        let queue = QueueStore::new(Duration::from_secs(3600), 100, 4 * bytes);
        let barrier = Barrier::new(THREADS);
        let accepted = thread::scope(|scope| {
            let handles = (0..THREADS)
                .map(|index| {
                    let queue = &queue;
                    let barrier = &barrier;
                    scope.spawn(move || {
                        let recipient = format!("{index:04}");
                        barrier.wait();
                        queue
                            .enqueue(recipient.clone(), Uuid::new_v4(), "blob".into())
                            .is_ok()
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| usize::from(handle.join().unwrap()))
                .sum::<usize>()
        });
        assert_eq!(accepted, 4);
        assert_eq!(total_bytes(&queue), 4 * bytes);
        assert_eq!(queue.queues.len(), 4);
    }

    #[test]
    fn concurrent_removal_and_requeue_keep_accounting_consistent() {
        let queue = QueueStore::new(Duration::from_secs(3600), 8, 4096);
        thread::scope(|scope| {
            for index in 0..8 {
                let queue = &queue;
                scope.spawn(move || {
                    let recipient = format!("{index:04}");
                    for turn in 0..100 {
                        let id = Uuid::new_v4();
                        let _ = queue.enqueue(recipient.clone(), id, "blob".into());
                        if turn % 2 == 0 {
                            queue.requeue_messages(queue.take_all_for_recipient(&recipient));
                        } else {
                            queue.dequeue_message(&recipient, id);
                        }
                        queue.purge_expired();
                        assert!(total_bytes(queue) <= 4096);
                    }
                });
            }
        });
        let accounted: usize = queue.queues.iter().map(|entry| entry.queued_bytes).sum();
        assert_eq!(total_bytes(&queue), accounted);
        for index in 0..8 {
            queue.take_all_for_recipient(&format!("{index:04}"));
        }
        assert_eq!(total_bytes(&queue), 0);
        assert!(queue.queues.is_empty());
    }

    #[test]
    fn dedup_prevents_duplicate_enqueue() {
        let queue = QueueStore::new(Duration::from_secs(3600), 100, 1024 * 1024);
        let recipient = "abcd".to_string();
        let id = Uuid::new_v4();

        let first = queue
            .enqueue(recipient.clone(), id, "blob".to_string())
            .unwrap();
        let second = queue
            .enqueue(recipient.clone(), id, "blob".to_string())
            .unwrap();

        assert!(first.0);
        assert!(!second.0);
        assert_eq!(queue.depth_for(&recipient), 1);
    }

    #[test]
    fn concurrent_enqueue_dedup_is_atomic() {
        const THREADS: usize = 32;

        let queue = Arc::new(QueueStore::new(Duration::from_secs(3600), 100, 1024 * 1024));
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
                    queue
                        .enqueue((*recipient).clone(), id, "blob".to_string())
                        .unwrap()
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

    #[test]
    fn take_all_for_recipient_returns_fifo_messages_and_clears_queue() {
        let queue = QueueStore::new(Duration::from_secs(3600), 100, 1024 * 1024);
        let recipient = "abcd".to_string();
        let ids = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];

        for (index, id) in ids.into_iter().enumerate() {
            let (queued, depth) = queue
                .enqueue(recipient.clone(), id, format!("blob-{index}"))
                .unwrap();
            assert!(queued);
            assert_eq!(depth, index + 1);
        }

        let drained = queue.take_all_for_recipient(&recipient);
        let drained_ids = drained
            .iter()
            .map(|message| message.message_id)
            .collect::<Vec<_>>();

        assert_eq!(drained_ids, ids);
        assert_eq!(queue.depth_for(&recipient), 0);
        assert!(queue.messages_for_recipient(&recipient).is_empty());
    }
}
