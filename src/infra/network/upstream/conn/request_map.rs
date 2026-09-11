// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Lock-free request/response correlation map.
//!
//! The upstream connection pool already bounds per-connection inflight queries,
//! so mapping the entire u16 DNS ID space for every connection wastes memory.
//! This implementation keeps the wire ID space intact while storing only the
//! active requests in a fixed-capacity sparse table.
//!
//! # Slot State Machine
//!
//! Each slot is described by a compact `meta` word plus inline sender storage.
//! The high bits of `meta` encode a small state machine:
//!
//! - `EMPTY` The slot has no live request and no probe-chain history that
//!   matters. Lookup can stop when it sees this state because linear probing
//!   guarantees the target key cannot exist later in the chain.
//! - `RESERVED` A transient hand-off state used while a thread is publishing or
//!   removing a slot. Other threads must treat it as occupied and retry/skip so
//!   they never observe a half-written sender pointer or race a concurrent
//!   detach.
//! - `FULL` The slot contains a stable `query_id -> Sender<Message>` mapping
//!   and can be matched by `take()` or `remove()`.
//! - `TOMBSTONE` The slot used to hold an entry but was deleted. We cannot
//!   collapse it to `EMPTY` immediately because older probe chains may still
//!   need to continue past this position. Insertions may reuse tombstones, and
//!   the table resets them back to `EMPTY` when the map becomes empty.
//!
//! The resulting lifecycle is:
//!
//! - insert: `EMPTY/TOMBSTONE -> RESERVED -> FULL`
//! - remove/take: `FULL -> RESERVED -> TOMBSTONE`
//! - reset/clear: `TOMBSTONE -> EMPTY`
//!
//! # Concurrency Notes
//!
//! - `store()` first claims a slot by moving `meta` to `RESERVED`, then writes
//!   the inline sender, then publishes the final `FULL` state with `Release`.
//! - `take()` and `remove()` first move a `FULL` slot back to `RESERVED`, then
//!   move the inline sender out, then leave a `TOMBSTONE`.
//! - `clear()` is the shutdown path. It forcibly drops every sender and
//!   rewrites all slots back to `EMPTY` so connection close can promptly
//!   unblock waiters.

use std::cell::UnsafeCell;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash, Hasher};
use std::hint::spin_loop;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};

use tokio::sync::oneshot::Sender;

use crate::infra::error::{DnsError, Result};
use crate::proto::{Message, MessageType};

const ID_SPACE_SIZE: u32 = u16::MAX as u32 + 1;
const MIN_SLOT_COUNT: usize = 8;
const SLOT_FACTOR: usize = 4;
const ID_HASH_DOMAIN: u64 = u64::from_be_bytes(*b"IDPERMUT");
const ID_PERMUTATION_ROUNDS: usize = 4;

/// Slot has never been used or has been fully reset.
const STATE_EMPTY: u32 = 0;
/// Slot is being published or removed and is not safe to consume.
const STATE_RESERVED: u32 = 1;
/// Slot contains a live `query_id -> sender` mapping.
const STATE_FULL: u32 = 2;
/// Slot was removed but must keep probe-chain continuity until reset.
const STATE_TOMBSTONE: u32 = 3;

const ID_MASK: u32 = 0x0000_FFFF;
const META_EMPTY: u32 = pack_meta(STATE_EMPTY, 0);
const META_TOMBSTONE: u32 = pack_meta(STATE_TOMBSTONE, 0);

const fn pack_meta(state: u32, id: u16) -> u32 {
    (state << 16) | id as u32
}

const fn meta_state(meta: u32) -> u32 {
    meta >> 16
}

const fn meta_id(meta: u32) -> u16 {
    (meta & ID_MASK) as u16
}

#[derive(Debug)]
struct Slot {
    meta: AtomicU32,
    fingerprint: AtomicU64,
    sender: UnsafeCell<MaybeUninit<Sender<Message>>>,
}

impl Slot {
    fn empty() -> Self {
        Self {
            meta: AtomicU32::new(META_EMPTY),
            fingerprint: AtomicU64::new(0),
            sender: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }
}

// Safety: the slot state machine guarantees that only the thread that owns a
// slot in RESERVED state may read, write, or drop the inline sender storage.
unsafe impl Sync for Slot {}

#[derive(Debug)]
pub struct RequestGuard<'a> {
    request_map: &'a RequestMap,
    query_id: u16,
    armed: bool,
}

impl RequestGuard<'_> {
    #[inline]
    pub fn query_id(&self) -> u16 {
        self.query_id
    }

    #[inline]
    pub fn disarm(&mut self) {
        self.armed = false;
    }

    #[inline]
    pub fn remove(&mut self) -> bool {
        if !self.armed {
            return false;
        }
        self.armed = false;
        self.request_map.remove(self.query_id)
    }
}

impl Drop for RequestGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.request_map.remove(self.query_id);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoreResult {
    Stored(u16),
    Retry,
    Exhausted,
}

/// Lock-free request correlation map with bounded sparse storage.
///
/// The table is deliberately overprovisioned relative to `max_inflight` so the
/// average probe chain stays short while the per-connection memory footprint
/// remains in the KB range instead of scaling with all 65536 DNS IDs.
pub struct RequestMap {
    slots: Box<[Slot]>,
    mask: usize,
    id_sequence: AtomicU16,
    id_rounds: [[u8; 256]; ID_PERMUTATION_ROUNDS],
    size: AtomicU16,
    hash_state: RandomState,
}

impl std::fmt::Debug for RequestMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestMap")
            .field("slot_count", &self.slots.len())
            .field("mask", &self.mask)
            .field("id_sequence", &self.id_sequence)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl RequestMap {
    /// Create a new sparse request map sized for the expected max inflight
    /// load.
    pub fn with_capacity(max_inflight: u16) -> Self {
        // Keep the table sparse on purpose. At the default inflight limit of
        // 64, we allocate 256 slots, which is still tiny but keeps
        // linear probing short even under bursty request churn.
        let desired = usize::from(max_inflight).saturating_mul(SLOT_FACTOR);
        let slot_count = desired.max(MIN_SLOT_COUNT).next_power_of_two();
        let mut slots = Vec::with_capacity(slot_count);
        for _ in 0..slot_count {
            slots.push(Slot::empty());
        }
        let hash_state = RandomState::new();
        let mut id_rounds = [[0u8; 256]; ID_PERMUTATION_ROUNDS];
        for (round, table) in id_rounds.iter_mut().enumerate() {
            for half in u8::MIN..=u8::MAX {
                table[usize::from(half)] = hash_state.hash_one((ID_HASH_DOMAIN, round, half)) as u8;
            }
        }

        Self {
            slots: slots.into_boxed_slice(),
            mask: slot_count - 1,
            id_sequence: AtomicU16::new(0),
            id_rounds,
            size: AtomicU16::new(0),
            hash_state,
        }
    }

    #[cfg(test)]
    #[inline(always)]
    pub fn store(&self, tx: Sender<Message>) -> Result<RequestGuard<'_>> {
        self.store_inner(tx, 0)
    }

    /// Store a DNS request together with a compact fingerprint of the request
    /// opcode and question section.
    ///
    /// The fingerprint lets the receive path reject a delayed or malformed
    /// response for a different question that happens to reuse the same 16-bit
    /// DNS ID without removing the live request from the map. `RandomState`
    /// keeps hash-collision behavior unpredictable. This is correlation, not
    /// authentication: a response carrying the same ID and question still
    /// matches. The common single-question case adds no heap allocation.
    #[inline(always)]
    pub fn store_for_request(
        &self,
        tx: Sender<Message>,
        request: &Message,
    ) -> Result<RequestGuard<'_>> {
        self.store_inner(tx, self.fingerprint(request))
    }

    #[inline(always)]
    fn store_inner(&self, tx: Sender<Message>, fingerprint: u64) -> Result<RequestGuard<'_>> {
        let mut tx = Some(tx);

        for _ in 0..ID_SPACE_SIZE {
            let id = self.next_start_id();
            match self.try_store_candidate(id, fingerprint, &mut tx) {
                StoreResult::Stored(id) => {
                    return Ok(RequestGuard {
                        request_map: self,
                        query_id: id,
                        armed: true,
                    });
                }
                StoreResult::Retry => continue,
                StoreResult::Exhausted => break,
            }
        }

        Err(DnsError::protocol(format!(
            "request map exhausted: table full (slots={}, active={})",
            self.slots.len(),
            self.size()
        )))
    }

    #[cfg(test)]
    #[inline(always)]
    pub fn take(&self, id: u16) -> Option<Sender<Message>> {
        self.detach(id)
    }

    /// Remove and return a pending request only when the DNS response matches
    /// the request fingerprint stored for this ID.
    ///
    /// A mismatch deliberately leaves the slot untouched so the real response
    /// may still arrive later. This must be paired with
    /// [`Self::store_for_request`].
    #[inline(always)]
    pub fn take_for_response(&self, id: u16, response: &Message) -> Option<Sender<Message>> {
        if response.message_type() != MessageType::Response {
            return None;
        }
        self.detach_matching(id, self.fingerprint(response))
    }

    #[inline(always)]
    pub fn remove(&self, id: u16) -> bool {
        let Some(sender) = self.detach(id) else {
            return false;
        };
        drop(sender);
        true
    }

    /// Remove and drop every pending sender currently tracked by this map.
    pub fn clear(&self) -> u16 {
        self.clear_inner(|_| {})
    }

    #[inline]
    fn clear_inner<F>(&self, mut after_slot: F) -> u16
    where
        F: FnMut(usize),
    {
        let mut removed = 0u16;
        for (idx, slot) in self.slots.iter().enumerate() {
            loop {
                let meta = slot.meta.load(Ordering::Acquire);
                match meta_state(meta) {
                    STATE_EMPTY => break,
                    STATE_TOMBSTONE => {
                        let _ = slot.meta.compare_exchange(
                            meta,
                            META_EMPTY,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        );
                        break;
                    }
                    STATE_RESERVED => {
                        spin_loop();
                    }
                    STATE_FULL => {
                        if slot
                            .meta
                            .compare_exchange(
                                meta,
                                pack_meta(STATE_RESERVED, meta_id(meta)),
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_err()
                        {
                            continue;
                        }

                        unsafe {
                            (*slot.sender.get()).assume_init_drop();
                        }
                        // Every published FULL slot has already incremented
                        // `size` before becoming observable. Decrement exactly
                        // the entry we successfully claimed instead of
                        // resetting the whole counter
                        // after the scan: a concurrent insert
                        // into an earlier slot may legitimately survive this
                        // clear pass.
                        self.size.fetch_sub(1, Ordering::Relaxed);
                        removed = removed.saturating_add(1);
                        slot.meta.store(META_EMPTY, Ordering::Release);
                        break;
                    }
                    _ => unreachable!("invalid request map slot state"),
                }
            }
            after_slot(idx);
        }
        removed
    }

    pub fn size(&self) -> u16 {
        self.size.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.size() == 0
    }

    #[inline(always)]
    fn try_store_candidate(
        &self,
        id: u16,
        fingerprint: u64,
        tx: &mut Option<Sender<Message>>,
    ) -> StoreResult {
        let mut tombstone = None;

        for step in 0..self.slots.len() {
            let idx = self.probe_index(id, step);
            let meta = self.slots[idx].meta.load(Ordering::Acquire);
            match meta_state(meta) {
                STATE_EMPTY => {
                    // We can stop probing at the first EMPTY slot. If we saw an
                    // earlier TOMBSTONE, reuse it; otherwise insert here.
                    let target = tombstone.unwrap_or(idx);
                    return if self.claim_slot(target, id, fingerprint, tx) {
                        StoreResult::Stored(id)
                    } else {
                        StoreResult::Retry
                    };
                }
                STATE_TOMBSTONE => {
                    // Keep the earliest tombstone so we preserve the usual
                    // linear-probing insertion rule while still recycling old
                    // slots as soon as possible.
                    if tombstone.is_none() {
                        tombstone = Some(idx);
                    }
                }
                STATE_RESERVED | STATE_FULL => {
                    if meta_id(meta) == id {
                        return StoreResult::Retry;
                    }
                }
                _ => unreachable!("invalid request map slot state"),
            }
        }

        if let Some(target) = tombstone {
            if self.claim_slot(target, id, fingerprint, tx) {
                StoreResult::Stored(id)
            } else {
                StoreResult::Retry
            }
        } else {
            StoreResult::Exhausted
        }
    }

    #[inline(always)]
    fn claim_slot(
        &self,
        idx: usize,
        id: u16,
        fingerprint: u64,
        tx: &mut Option<Sender<Message>>,
    ) -> bool {
        let slot = &self.slots[idx];

        loop {
            let meta = slot.meta.load(Ordering::Acquire);
            match meta_state(meta) {
                STATE_EMPTY | STATE_TOMBSTONE => {
                    // Claim the slot first, then publish the inline sender,
                    // then mark the slot FULL. Readers treat RESERVED as busy
                    // and will never observe a half-published entry.
                    if slot
                        .meta
                        .compare_exchange(
                            meta,
                            pack_meta(STATE_RESERVED, id),
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_err()
                    {
                        continue;
                    }

                    let tx = tx.take().expect("sender present after slot claim");
                    unsafe {
                        (*slot.sender.get()).write(tx);
                    }
                    slot.fingerprint.store(fingerprint, Ordering::Relaxed);
                    // Account for the live request before publishing FULL. A
                    // concurrent clear() treats RESERVED as in-flight and waits
                    // until publication completes, so any thread that observes
                    // FULL is guaranteed that the slot is already included in
                    // `size`.
                    self.size.fetch_add(1, Ordering::Relaxed);
                    slot.meta
                        .store(pack_meta(STATE_FULL, id), Ordering::Release);
                    return true;
                }
                STATE_RESERVED | STATE_FULL => return false,
                _ => unreachable!("invalid request map slot state"),
            }
        }
    }

    #[inline(always)]
    fn detach_matching(&self, id: u16, fingerprint: u64) -> Option<Sender<Message>> {
        for step in 0..self.slots.len() {
            let idx = self.probe_index(id, step);
            let slot = &self.slots[idx];
            let meta = slot.meta.load(Ordering::Acquire);
            match meta_state(meta) {
                STATE_EMPTY => return None,
                STATE_RESERVED | STATE_TOMBSTONE => continue,
                STATE_FULL => {
                    if meta_id(meta) != id {
                        continue;
                    }

                    if slot.fingerprint.load(Ordering::Relaxed) != fingerprint {
                        return None;
                    }

                    if slot
                        .meta
                        .compare_exchange(
                            meta,
                            pack_meta(STATE_RESERVED, id),
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_err()
                    {
                        continue;
                    }

                    let sender = unsafe { (*slot.sender.get()).assume_init_read() };
                    slot.meta.store(META_TOMBSTONE, Ordering::Release);
                    self.size.fetch_sub(1, Ordering::Relaxed);
                    if self.is_empty() {
                        self.reset_tombstones();
                    }
                    return Some(sender);
                }
                _ => unreachable!("invalid request map slot state"),
            }
        }
        None
    }

    #[inline(always)]
    fn detach(&self, id: u16) -> Option<Sender<Message>> {
        for step in 0..self.slots.len() {
            let idx = self.probe_index(id, step);
            let slot = &self.slots[idx];
            let meta = slot.meta.load(Ordering::Acquire);
            match meta_state(meta) {
                STATE_EMPTY => return None,
                STATE_RESERVED => continue,
                STATE_TOMBSTONE => continue,
                STATE_FULL => {
                    if meta_id(meta) != id {
                        continue;
                    }

                    // Move the slot back to RESERVED to become the sole owner
                    // of the inline sender before moving it out.
                    if slot
                        .meta
                        .compare_exchange(
                            meta,
                            pack_meta(STATE_RESERVED, id),
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_err()
                    {
                        continue;
                    }

                    let sender = unsafe { (*slot.sender.get()).assume_init_read() };
                    slot.meta.store(META_TOMBSTONE, Ordering::Release);
                    self.size.fetch_sub(1, Ordering::Relaxed);
                    if self.is_empty() {
                        // Once the map drains completely, we can safely turn
                        // all tombstones back into
                        // empty slots and restore short
                        // probe chains for the next burst of traffic.
                        self.reset_tombstones();
                    }
                    return Some(sender);
                }
                _ => unreachable!("invalid request map slot state"),
            }
        }
        None
    }

    fn reset_tombstones(&self) {
        if !self.is_empty() {
            return;
        }

        for slot in &self.slots {
            let meta = slot.meta.load(Ordering::Relaxed);
            if meta_state(meta) == STATE_TOMBSTONE {
                let _ = slot.meta.compare_exchange(
                    meta,
                    META_EMPTY,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                );
            }
        }
    }

    #[inline(always)]
    fn probe_index(&self, id: u16, step: usize) -> usize {
        let hash = usize::from(id).wrapping_mul(0x9E37_79B1usize);
        (hash.wrapping_add(step)) & self.mask
    }

    #[inline(always)]
    fn next_start_id(&self) -> u16 {
        let sequence = self.id_sequence.fetch_add(1, Ordering::Relaxed);
        self.permute_id(sequence)
    }

    /// Map the sequential allocation counter onto a keyed permutation of the
    /// entire 16-bit DNS transaction-ID space. Unlike truncating a wider hash,
    /// this cannot repeat an ID within one complete 65536-allocation cycle.
    #[inline(always)]
    fn permute_id(&self, input: u16) -> u16 {
        let mut left = (input >> 8) as u8;
        let mut right = input as u8;

        for table in &self.id_rounds {
            let mixed = table[usize::from(right)];
            (left, right) = (right, left ^ mixed);
        }

        (u16::from(left) << 8) | u16::from(right)
    }

    #[inline(always)]
    fn fingerprint(&self, message: &Message) -> u64 {
        let mut hasher = self.hash_state.build_hasher();
        message.opcode().hash(&mut hasher);
        message.questions().len().hash(&mut hasher);
        for question in message.questions() {
            question.name().hash(&mut hasher);
            question.qtype().hash(&mut hasher);
            question.qclass().hash(&mut hasher);
        }
        hasher.finish()
    }
}

impl Drop for RequestMap {
    fn drop(&mut self) {
        let _ = self.clear();
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::oneshot;

    use super::*;
    use crate::proto::{DNSClass, Name, Question, RecordType};

    fn make_message(id: u16) -> Message {
        let mut message = Message::new();
        message.set_id(id);
        message
    }

    fn make_query(name: &str, qtype: RecordType) -> Message {
        let mut message = Message::new();
        message.add_question(Question::new(
            Name::from_ascii(name).expect("test qname should parse"),
            qtype,
            DNSClass::IN,
        ));
        message
    }

    fn make_response(request: &Message, id: u16) -> Message {
        let mut response = request.clone();
        response.set_id(id);
        response.set_message_type(MessageType::Response);
        response
    }

    #[test]
    fn test_with_capacity_uses_sparse_slot_count() {
        let map = RequestMap::with_capacity(64);

        assert_eq!(map.slots.len(), 256);
        assert_eq!(map.mask, 255);
    }

    #[test]
    fn test_store_returns_retrievable_sender_and_updates_size() {
        let map = RequestMap::with_capacity(8);
        let (tx, rx) = oneshot::channel();

        let mut guard = map.store(tx).expect("store should succeed");
        let id = guard.query_id();

        assert_eq!(map.size(), 1);
        let sender = map.take(id).expect("stored sender should be retrievable");
        guard.disarm();
        assert_eq!(map.size(), 0);
        assert!(sender.send(make_message(7)).is_ok());
        let received = rx.blocking_recv().expect("receiver should get the message");
        assert_eq!(received.id(), 7);
    }

    #[test]
    fn test_take_missing_id_returns_none_without_changing_size() {
        let map = RequestMap::with_capacity(8);

        assert!(map.take(42).is_none());
        assert_eq!(map.size(), 0);
        assert!(map.is_empty());
    }

    #[test]
    fn test_take_twice_only_returns_sender_once() {
        let map = RequestMap::with_capacity(8);
        let (tx, _rx) = oneshot::channel();
        let mut guard = map.store(tx).expect("store should succeed");
        let id = guard.query_id();

        assert!(map.take(id).is_some());
        guard.disarm();
        assert!(map.take(id).is_none());
        assert!(map.is_empty());
    }

    #[test]
    fn test_take_for_response_accepts_matching_question_fingerprint() {
        let map = RequestMap::with_capacity(8);
        let request = make_query("example.com", RecordType::A);
        let (tx, rx) = oneshot::channel();
        let mut guard = map
            .store_for_request(tx, &request)
            .expect("store should succeed");
        let id = guard.query_id();
        let response = make_response(&request, id);

        let sender = map
            .take_for_response(id, &response)
            .expect("matching response should detach sender");
        guard.disarm();
        assert!(sender.send(response).is_ok());
        assert!(rx.blocking_recv().is_ok());
        assert!(map.is_empty());
    }

    #[test]
    fn test_take_for_response_rejects_mismatch_without_removing_request() {
        let map = RequestMap::with_capacity(8);
        let request = make_query("example.com", RecordType::A);
        let (tx, _rx) = oneshot::channel();
        let mut guard = map
            .store_for_request(tx, &request)
            .expect("store should succeed");
        let id = guard.query_id();

        let wrong_request = make_query("example.com", RecordType::AAAA);
        let wrong_response = make_response(&wrong_request, id);
        assert!(map.take_for_response(id, &wrong_response).is_none());
        assert_eq!(map.size(), 1, "mismatch must leave request pending");

        let response = make_response(&request, id);
        assert!(map.take_for_response(id, &response).is_some());
        guard.disarm();
        assert!(map.is_empty());
    }

    #[test]
    fn test_take_for_response_rejects_query_packet() {
        let map = RequestMap::with_capacity(8);
        let request = make_query("example.com", RecordType::A);
        let (tx, _rx) = oneshot::channel();
        let mut guard = map
            .store_for_request(tx, &request)
            .expect("store should succeed");
        let id = guard.query_id();
        let mut query_packet = request.clone();
        query_packet.set_id(id);

        assert!(map.take_for_response(id, &query_packet).is_none());
        assert_eq!(map.size(), 1, "query packet must leave request pending");
        assert!(guard.remove());
    }

    #[test]
    fn test_store_after_take_keeps_map_usable() {
        let map = RequestMap::with_capacity(8);
        let (tx1, _rx1) = oneshot::channel();
        let mut guard1 = map.store(tx1).expect("store should succeed");
        let id1 = guard1.query_id();
        let _ = map.take(id1);
        guard1.disarm();

        let (tx2, rx2) = oneshot::channel();
        let mut guard2 = map.store(tx2).expect("store should succeed");
        let id2 = guard2.query_id();
        let sender = map.take(id2).expect("second sender should be retrievable");
        guard2.disarm();

        assert!(sender.send(make_message(9)).is_ok());
        assert_eq!(
            rx2.blocking_recv()
                .expect("receiver should get the second message")
                .id(),
            9
        );
    }

    #[test]
    fn test_remove_drops_sender_and_updates_size() {
        let map = RequestMap::with_capacity(8);
        let (tx, rx) = oneshot::channel::<Message>();
        let mut guard = map.store(tx).expect("store should succeed");
        let id = guard.query_id();

        assert!(guard.remove());
        assert_eq!(map.size(), 0);
        assert!(map.is_empty());
        assert!(map.take(id).is_none());
        assert!(rx.blocking_recv().is_err());
    }

    #[test]
    fn test_drop_releases_pending_senders() {
        let (tx, rx) = oneshot::channel::<Message>();
        let map = RequestMap::with_capacity(8);
        let guard = map.store(tx).expect("store should succeed");
        std::mem::forget(guard);

        drop(map);

        assert!(rx.blocking_recv().is_err());
    }

    #[test]
    fn test_remove_missing_id_returns_false_without_changing_size() {
        let map = RequestMap::with_capacity(8);
        let (tx, _rx) = oneshot::channel();
        let _guard = map.store(tx).expect("store should succeed");

        assert!(!map.remove(42));
        assert_eq!(map.size(), 1);
    }

    #[test]
    fn test_clear_drops_all_pending_senders() {
        let map = RequestMap::with_capacity(8);
        let (tx1, rx1) = oneshot::channel::<Message>();
        let (tx2, rx2) = oneshot::channel::<Message>();
        let guard1 = map.store(tx1).expect("store should succeed");
        let guard2 = map.store(tx2).expect("store should succeed");

        assert_eq!(map.clear(), 2);
        assert_eq!(map.size(), 0);
        assert!(map.is_empty());
        drop(guard1);
        drop(guard2);
        assert!(rx1.blocking_recv().is_err());
        assert!(rx2.blocking_recv().is_err());
    }

    #[test]
    fn test_clear_preserves_count_for_insert_after_scanned_slot() {
        use std::sync::{Arc, Barrier};

        let map = Arc::new(RequestMap::with_capacity(1));
        let after_first_slot = Arc::new(Barrier::new(2));
        let resume_clear = Arc::new(Barrier::new(2));

        let clear_map = Arc::clone(&map);
        let clear_after_first = Arc::clone(&after_first_slot);
        let clear_resume = Arc::clone(&resume_clear);
        let clear_thread = std::thread::spawn(move || {
            clear_map.clear_inner(|idx| {
                if idx == 0 {
                    clear_after_first.wait();
                    clear_resume.wait();
                }
            })
        });

        // Wait until clear() has observed slot 0 as EMPTY, then publish a live
        // entry into exactly that already-scanned slot. This is the shutdown
        // race that used to be corrupted by the final `size.store(0)`.
        after_first_slot.wait();
        let id = (u16::MIN..=u16::MAX)
            .find(|id| map.probe_index(*id, 0) == 0)
            .expect("an ID must hash to slot 0");
        let (tx, _rx) = oneshot::channel::<Message>();
        let mut tx = Some(tx);
        assert!(map.claim_slot(0, id, 0, &mut tx));
        assert_eq!(map.size(), 1);

        resume_clear.wait();
        assert_eq!(clear_thread.join().expect("clear thread should finish"), 0);
        assert_eq!(
            map.size(),
            1,
            "clear must not erase the count of an insert into an already-scanned slot"
        );

        assert!(map.remove(id));
        assert_eq!(map.size(), 0);
        assert!(map.is_empty());
    }

    #[test]
    fn test_failed_slot_claim_preserves_sender_for_retry() {
        let map = RequestMap::with_capacity(1);
        let (first_tx, _first_rx) = oneshot::channel::<Message>();
        let mut first_tx = Some(first_tx);
        assert!(map.claim_slot(0, 1, 0, &mut first_tx));
        assert!(first_tx.is_none());

        let (retry_tx, _retry_rx) = oneshot::channel::<Message>();
        let mut retry_tx = Some(retry_tx);
        assert!(!map.claim_slot(0, 2, 0, &mut retry_tx));
        assert!(retry_tx.is_some(), "failed claim must preserve sender");

        assert_eq!(map.clear(), 1);
    }

    #[test]
    fn test_id_permutation_covers_full_space_without_reuse() {
        let map = RequestMap::with_capacity(8);
        let mut seen = vec![false; ID_SPACE_SIZE as usize];

        for input in 0..=u16::MAX {
            let id = map.permute_id(input);
            assert!(!seen[usize::from(id)], "duplicate permuted DNS ID: {id}");
            seen[usize::from(id)] = true;
        }

        assert!(seen.into_iter().all(|used| used));
    }

    #[test]
    fn test_id_sequence_wraparound_remains_usable() {
        let map = RequestMap::with_capacity(8);
        map.id_sequence.store(u16::MAX - 1, Ordering::Relaxed);

        let (tx1, _rx1) = oneshot::channel();
        let mut first = map.store(tx1).expect("store should succeed");
        let (tx2, _rx2) = oneshot::channel();
        let mut second = map.store(tx2).expect("store should succeed");
        let (tx3, _rx3) = oneshot::channel();
        let mut third = map.store(tx3).expect("store should succeed");

        assert_eq!(map.id_sequence.load(Ordering::Relaxed), 1);
        assert_ne!(first.query_id(), second.query_id());
        assert_ne!(first.query_id(), third.query_id());
        assert_ne!(second.query_id(), third.query_id());
        assert!(first.remove());
        assert!(second.remove());
        assert!(third.remove());
    }

    #[test]
    fn test_tombstones_reset_when_map_becomes_empty() {
        let map = RequestMap::with_capacity(1);
        let (tx, _rx) = oneshot::channel();
        let mut guard = map.store(tx).expect("store should succeed");

        assert!(guard.remove());
        assert!(map.is_empty());
        assert!(
            map.slots
                .iter()
                .all(|slot| meta_state(slot.meta.load(Ordering::Relaxed)) == STATE_EMPTY)
        );
    }

    #[test]
    fn test_store_returns_error_when_table_is_full() {
        let map = RequestMap::with_capacity(1);
        let mut guards = Vec::new();
        for _ in 0..map.slots.len() {
            let (tx, _rx) = oneshot::channel::<Message>();
            let guard = map
                .store(tx)
                .expect("store should succeed while capacity remains");
            guards.push(guard);
        }

        let (tx, _rx) = oneshot::channel::<Message>();
        let err = map
            .store(tx)
            .expect_err("store should fail after table is full");

        assert!(err.to_string().contains("request map exhausted"));
        drop(guards);
    }

    #[test]
    fn test_request_guard_drop_removes_pending_request() {
        let map = RequestMap::with_capacity(1);
        let (tx, _rx) = oneshot::channel::<Message>();
        let guard = map.store(tx).expect("store should succeed");

        assert_eq!(map.size(), 1);
        drop(guard);
        assert_eq!(map.size(), 0);
        assert!(map.is_empty());
    }
}
