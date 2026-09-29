// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{
    Receiver as ReplyReceiver, RecvTimeoutError, Sender as ReplySender, SyncSender, TrySendError,
    sync_channel,
};
use std::sync::{
    Arc, Mutex, MutexGuard, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockError, Weak,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rusqlite::{Connection, InterruptHandle};
use tokio::sync::{Semaphore, broadcast};
use tracing::{error, info, warn};

use super::model::{PendingRecord, RecordDetail, ResolvedRecorderConfig, TableNames};
use super::store::{create_schema, open_writer_database, run_writer_thread, table_names};
use crate::infra::error::{DnsError, Result};

const DROP_WARN_INTERVAL: Duration = Duration::from_secs(5);
const COORDINATOR_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MANAGEMENT_START_TIMEOUT: Duration = Duration::from_secs(1);
const MANAGEMENT_OPERATION_TIMEOUT: Duration = Duration::from_secs(300);
const SHUTDOWN_ENQUEUE_TIMEOUT: Duration = Duration::from_millis(500);
const SHUTDOWN_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);
const SHUTDOWN_QUEUE_RETRY_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Copy)]
enum DropKind {
    QueueFull,
    WriterDisconnected,
    Oversized,
}

#[derive(Debug, Default)]
struct DropLogState {
    last_warn: Option<Instant>,
}

#[derive(Default)]
pub(super) struct WriterInterrupt {
    handle: Mutex<Option<InterruptHandle>>,
}

impl std::fmt::Debug for WriterInterrupt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriterInterrupt").finish_non_exhaustive()
    }
}

impl WriterInterrupt {
    pub(super) fn install(&self, conn: &Connection) {
        let mut guard = self
            .handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(conn.get_interrupt_handle());
    }

    pub(super) fn interrupt(&self) {
        let guard = self
            .handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(handle) = guard.as_ref() {
            handle.interrupt();
        }
    }

    pub(super) fn clear(&self) {
        let mut guard = self
            .handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = None;
    }
}

#[derive(Debug)]
pub(super) struct RecorderBackend {
    pub(super) tag: String,
    pub(super) path: PathBuf,
    pub(super) tables: TableNames,
    pub(super) queue_tx: SyncSender<WriterCommand>,
    pub(super) stop_requested: Arc<AtomicBool>,
    pub(super) writer_handle: Mutex<Option<JoinHandle<()>>>,
    pub(super) tail: Arc<Mutex<VecDeque<RecordDetail>>>,
    pub(super) memory_tail: usize,
    pub(super) broadcaster: broadcast::Sender<RecordDetail>,
    pub(super) dropped_total: Arc<AtomicU64>,
    pub(super) reader_semaphore: Arc<Semaphore>,
    pub(super) database_coordinator: Arc<DatabaseCoordinator>,
    writer_interrupt: Arc<WriterInterrupt>,
    accepting_records: AtomicBool,
    writer_recovering: Arc<AtomicBool>,
    management_inflight: Arc<AtomicBool>,
    drop_log_state: Mutex<DropLogState>,
    drop_queue_full: AtomicU64,
    drop_writer_disconnected: AtomicU64,
    drop_oversized: AtomicU64,
}

#[derive(Debug, Clone)]
pub(super) struct SpaceStats {
    pub(super) auto_vacuum: i64,
    pub(super) page_size: u64,
    pub(super) page_count: u64,
    pub(super) freelist_count: u64,
    pub(super) database_bytes: u64,
    pub(super) wal_bytes: u64,
}

impl SpaceStats {
    pub(super) fn total_bytes(&self) -> u64 {
        self.database_bytes.saturating_add(self.wal_bytes)
    }
}

#[derive(Debug, Clone)]
pub(super) struct SpaceReclaimResult {
    pub(super) before: SpaceStats,
    pub(super) reclaimable: SpaceStats,
    pub(super) after: SpaceStats,
    pub(super) migrated: bool,
    pub(super) peak_wal_bytes: u64,
}

impl SpaceReclaimResult {
    pub(super) fn reclaimed_bytes(&self) -> u64 {
        self.before
            .total_bytes()
            .saturating_sub(self.after.total_bytes())
    }
}

#[derive(Debug, Clone)]
pub(super) struct CleanupResult {
    pub(super) deleted_records: usize,
    pub(super) space: SpaceReclaimResult,
}

#[derive(Debug, Clone)]
pub(super) struct ClearHistoryResult {
    pub(super) cleared_records: usize,
    pub(super) space: SpaceReclaimResult,
}

pub(super) type CleanupReply = std::result::Result<CleanupResult, String>;
pub(super) type ClearHistoryReply = std::result::Result<ClearHistoryResult, String>;
#[cfg(test)]
pub(super) type FlushReply = std::result::Result<(), String>;

#[derive(Debug)]
pub(super) enum WriterCommand {
    Insert(Box<PendingRecord>),
    Cleanup {
        cutoff_ms: i64,
        started_tx: ReplySender<()>,
        reply_tx: ReplySender<CleanupReply>,
        cancelled: Arc<AtomicBool>,
    },
    ClearHistory {
        started_tx: ReplySender<()>,
        reply_tx: ReplySender<ClearHistoryReply>,
        cancelled: Arc<AtomicBool>,
    },
    Shutdown {
        reply_tx: ReplySender<std::result::Result<(), String>>,
    },
    #[cfg(test)]
    Flush {
        reply_tx: ReplySender<FlushReply>,
    },
}

#[derive(Debug)]
pub(super) struct WriterThreadContext {
    pub(super) path: PathBuf,
    pub(super) tables: TableNames,
    pub(super) stop_requested: Arc<AtomicBool>,
    pub(super) tail: Arc<Mutex<VecDeque<RecordDetail>>>,
    pub(super) memory_tail: usize,
    pub(super) broadcaster: broadcast::Sender<RecordDetail>,
    pub(super) batch_size: usize,
    pub(super) flush_interval: Duration,
    pub(super) database_coordinator: Arc<DatabaseCoordinator>,
    pub(super) dropped_total: Arc<AtomicU64>,
    pub(super) writer_interrupt: Arc<WriterInterrupt>,
    pub(super) writer_recovering: Arc<AtomicBool>,
    pub(super) management_inflight: Arc<AtomicBool>,
}

#[derive(Debug, Default)]
pub(super) struct DatabaseCoordinator {
    access: RwLock<()>,
    writer: Mutex<()>,
    waiting_writers: AtomicUsize,
}

pub(super) struct DatabaseWriteGuard<'a> {
    _guard: RwLockWriteGuard<'a, ()>,
    waiting_writers: &'a AtomicUsize,
}

impl Drop for DatabaseWriteGuard<'_> {
    fn drop(&mut self) {
        self.waiting_writers.fetch_sub(1, Ordering::AcqRel);
    }
}

impl DatabaseCoordinator {
    pub(super) fn read_access(&self) -> Result<RwLockReadGuard<'_, ()>> {
        loop {
            if self.waiting_writers.load(Ordering::Acquire) != 0 {
                thread::sleep(COORDINATOR_LOCK_POLL_INTERVAL);
                continue;
            }
            match self.access.try_read() {
                Ok(guard) => {
                    if self.waiting_writers.load(Ordering::Acquire) == 0 {
                        return Ok(guard);
                    }
                    drop(guard);
                    thread::sleep(COORDINATOR_LOCK_POLL_INTERVAL);
                }
                Err(TryLockError::WouldBlock) => {
                    thread::sleep(COORDINATOR_LOCK_POLL_INTERVAL);
                }
                Err(TryLockError::Poisoned(_)) => {
                    return Err(DnsError::runtime(
                        "query_recorder database access lock poisoned",
                    ));
                }
            }
        }
    }

    pub(super) fn write_access(&self) -> Result<DatabaseWriteGuard<'_>> {
        self.waiting_writers.fetch_add(1, Ordering::AcqRel);
        loop {
            match self.access.try_write() {
                Ok(guard) => {
                    return Ok(DatabaseWriteGuard {
                        _guard: guard,
                        waiting_writers: &self.waiting_writers,
                    });
                }
                Err(TryLockError::WouldBlock) => {
                    thread::sleep(COORDINATOR_LOCK_POLL_INTERVAL);
                }
                Err(TryLockError::Poisoned(_)) => {
                    self.waiting_writers.fetch_sub(1, Ordering::AcqRel);
                    return Err(DnsError::runtime(
                        "query_recorder database access lock poisoned",
                    ));
                }
            }
        }
    }

    pub(super) fn read_access_until_stop(
        &self,
        stop_requested: &AtomicBool,
    ) -> Result<Option<RwLockReadGuard<'_, ()>>> {
        loop {
            if stop_requested.load(Ordering::Acquire) {
                return Ok(None);
            }
            if self.waiting_writers.load(Ordering::Acquire) != 0 {
                thread::sleep(COORDINATOR_LOCK_POLL_INTERVAL);
                continue;
            }
            match self.access.try_read() {
                Ok(guard) => {
                    if self.waiting_writers.load(Ordering::Acquire) == 0 {
                        return Ok(Some(guard));
                    }
                    drop(guard);
                    thread::sleep(COORDINATOR_LOCK_POLL_INTERVAL);
                }
                Err(TryLockError::WouldBlock) => {
                    thread::sleep(COORDINATOR_LOCK_POLL_INTERVAL);
                }
                Err(TryLockError::Poisoned(_)) => {
                    return Err(DnsError::runtime(
                        "query_recorder database access lock poisoned",
                    ));
                }
            }
        }
    }

    pub(super) fn write_access_until_stop(
        &self,
        stop_requested: &AtomicBool,
    ) -> Result<Option<DatabaseWriteGuard<'_>>> {
        self.waiting_writers.fetch_add(1, Ordering::AcqRel);
        loop {
            if stop_requested.load(Ordering::Acquire) {
                self.waiting_writers.fetch_sub(1, Ordering::AcqRel);
                return Ok(None);
            }
            match self.access.try_write() {
                Ok(guard) => {
                    return Ok(Some(DatabaseWriteGuard {
                        _guard: guard,
                        waiting_writers: &self.waiting_writers,
                    }));
                }
                Err(TryLockError::WouldBlock) => {
                    thread::sleep(COORDINATOR_LOCK_POLL_INTERVAL);
                }
                Err(TryLockError::Poisoned(_)) => {
                    self.waiting_writers.fetch_sub(1, Ordering::AcqRel);
                    return Err(DnsError::runtime(
                        "query_recorder database access lock poisoned",
                    ));
                }
            }
        }
    }

    pub(super) fn write_access_until_stop_or_cancel(
        &self,
        stop_requested: &AtomicBool,
        cancelled: &AtomicBool,
    ) -> Result<Option<DatabaseWriteGuard<'_>>> {
        self.waiting_writers.fetch_add(1, Ordering::AcqRel);
        loop {
            if stop_requested.load(Ordering::Acquire) {
                self.waiting_writers.fetch_sub(1, Ordering::AcqRel);
                return Ok(None);
            }
            if cancelled.load(Ordering::Acquire) {
                self.waiting_writers.fetch_sub(1, Ordering::AcqRel);
                return Err(DnsError::runtime(
                    "query_recorder management operation cancelled",
                ));
            }
            match self.access.try_write() {
                Ok(guard) => {
                    return Ok(Some(DatabaseWriteGuard {
                        _guard: guard,
                        waiting_writers: &self.waiting_writers,
                    }));
                }
                Err(TryLockError::WouldBlock) => {
                    thread::sleep(COORDINATOR_LOCK_POLL_INTERVAL);
                }
                Err(TryLockError::Poisoned(_)) => {
                    self.waiting_writers.fetch_sub(1, Ordering::AcqRel);
                    return Err(DnsError::runtime(
                        "query_recorder database access lock poisoned",
                    ));
                }
            }
        }
    }

    pub(super) fn writer_until_stop(
        &self,
        stop_requested: &AtomicBool,
    ) -> Result<Option<MutexGuard<'_, ()>>> {
        loop {
            if stop_requested.load(Ordering::Acquire) {
                return Ok(None);
            }
            match self.writer.try_lock() {
                Ok(guard) => return Ok(Some(guard)),
                Err(TryLockError::WouldBlock) => {
                    thread::sleep(COORDINATOR_LOCK_POLL_INTERVAL);
                }
                Err(TryLockError::Poisoned(_)) => {
                    return Err(DnsError::runtime(
                        "query_recorder database writer lock poisoned",
                    ));
                }
            }
        }
    }

    #[cfg(test)]
    pub(super) fn waiting_writers_for_test(&self) -> usize {
        self.waiting_writers.load(Ordering::Acquire)
    }

    fn exclusive_access_active_or_waiting(&self) -> bool {
        self.waiting_writers.load(Ordering::Acquire) != 0
    }
}

static DATABASE_COORDINATORS: OnceLock<Mutex<HashMap<PathBuf, Weak<DatabaseCoordinator>>>> =
    OnceLock::new();

fn database_coordinator(path: &Path) -> Result<Arc<DatabaseCoordinator>> {
    let path = canonical_database_path(path)?;
    let registry = DATABASE_COORDINATORS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut registry = registry
        .lock()
        .map_err(|_| DnsError::runtime("query_recorder coordinator registry lock poisoned"))?;
    registry.retain(|_, coordinator| coordinator.strong_count() > 0);
    if let Some(coordinator) = registry.get(&path).and_then(Weak::upgrade) {
        return Ok(coordinator);
    }
    let coordinator = Arc::new(DatabaseCoordinator::default());
    registry.insert(path, Arc::downgrade(&coordinator));
    Ok(coordinator)
}

fn canonical_database_path(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return Ok(std::fs::canonicalize(path)?);
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let canonical_parent = match parent {
        Some(parent) => std::fs::canonicalize(parent)?,
        None => std::env::current_dir()?,
    };
    let file_name = path
        .file_name()
        .ok_or_else(|| DnsError::plugin("query_recorder path must include a file name"))?;
    Ok(canonical_parent.join(file_name))
}

impl RecorderBackend {
    pub(super) fn run(tag: String, config: ResolvedRecorderConfig) -> Result<Arc<Self>> {
        if let Some(parent) = config.path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|err| {
                DnsError::plugin(format!(
                    "failed to create query_recorder directory '{}': {}",
                    parent.display(),
                    err
                ))
            })?;
        }

        let database_coordinator = database_coordinator(&config.path)?;
        let (conn, tables) = {
            let _access = database_coordinator.write_access()?;
            let mut conn = open_writer_database(&config.path).map_err(|err| {
                format!(
                    "failed to open database '{}': {}",
                    config.path.display(),
                    err
                )
            })?;

            let tables = table_names(&tag);
            create_schema(&mut conn, &tables)?;
            // Refresh query planner stats once at startup; this is the cheap
            // version of ANALYZE and is the recommended way to keep indexes
            // selectable across schema upgrades.
            if let Err(err) = conn.execute_batch("PRAGMA optimize;") {
                warn!("query_recorder PRAGMA optimize failed at startup: {}", err);
            }
            (conn, tables)
        };

        let (queue_tx, queue_rx) = sync_channel(config.queue_size);
        let stop_requested = Arc::new(AtomicBool::new(false));
        let tail = Arc::new(Mutex::new(VecDeque::with_capacity(
            config.memory_tail.max(1),
        )));
        let (broadcaster, _) = broadcast::channel(config.memory_tail.max(16));
        let dropped_total = Arc::new(AtomicU64::new(0));
        let reader_semaphore = Arc::new(Semaphore::new(config.reader_concurrency));
        let writer_interrupt = Arc::new(WriterInterrupt::default());
        let writer_recovering = Arc::new(AtomicBool::new(false));
        let management_inflight = Arc::new(AtomicBool::new(false));
        writer_interrupt.install(&conn);
        let writer_dropped_total = dropped_total.clone();
        let writer_interrupt_for_thread = writer_interrupt.clone();
        let writer_recovering_for_thread = writer_recovering.clone();
        let management_inflight_for_thread = management_inflight.clone();

        let writer_tables = tables.clone();
        let writer_path = config.path.clone();
        let writer_stop = stop_requested.clone();
        let writer_tail = tail.clone();
        let writer_broadcaster = broadcaster.clone();
        let memory_tail = config.memory_tail.max(1);
        let batch_size = config.batch_size;
        let flush_interval = Duration::from_millis(config.flush_interval_ms);
        let writer_database_coordinator = database_coordinator.clone();
        let writer_handle = thread::Builder::new()
            .name(format!("query-recorder-{}", tag))
            .spawn(move || {
                if let Err(err) = run_writer_thread(
                    WriterThreadContext {
                        path: writer_path,
                        tables: writer_tables,
                        stop_requested: writer_stop,
                        tail: writer_tail,
                        memory_tail,
                        broadcaster: writer_broadcaster,
                        batch_size,
                        flush_interval,
                        database_coordinator: writer_database_coordinator,
                        dropped_total: writer_dropped_total,
                        writer_interrupt: writer_interrupt_for_thread,
                        writer_recovering: writer_recovering_for_thread,
                        management_inflight: management_inflight_for_thread,
                    },
                    queue_rx,
                    conn,
                ) {
                    error!("query_recorder writer stopped: {}", err);
                }
            })?;

        Ok(Arc::new(Self {
            tag,
            path: config.path,
            tables,
            queue_tx,
            stop_requested,
            writer_handle: Mutex::new(Some(writer_handle)),
            tail,
            memory_tail,
            broadcaster,
            dropped_total,
            reader_semaphore,
            database_coordinator,
            writer_interrupt,
            accepting_records: AtomicBool::new(true),
            writer_recovering,
            management_inflight,
            drop_log_state: Mutex::new(DropLogState::default()),
            drop_queue_full: AtomicU64::new(0),
            drop_writer_disconnected: AtomicU64::new(0),
            drop_oversized: AtomicU64::new(0),
        }))
    }

    pub(super) fn enqueue(&self, pending: PendingRecord) {
        if !self.accepting_records.load(Ordering::Relaxed) {
            return;
        }
        match self
            .queue_tx
            .try_send(WriterCommand::Insert(Box::new(pending)))
        {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => self.record_drop(DropKind::QueueFull),
            Err(TrySendError::Disconnected(_)) => self.record_drop(DropKind::WriterDisconnected),
        }
    }

    fn hard_stop(&self) {
        self.stop_requested.store(true, Ordering::Release);
        self.writer_interrupt.interrupt();
    }

    pub(super) fn shutdown(&self) {
        self.accepting_records.store(false, Ordering::Release);
        if self.writer_recovering.load(Ordering::Acquire)
            || self.management_inflight.load(Ordering::Acquire)
            || self
                .database_coordinator
                .exclusive_access_active_or_waiting()
        {
            self.hard_stop();
            return;
        }

        let enqueue_deadline = Instant::now() + SHUTDOWN_ENQUEUE_TIMEOUT;
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        let mut command = WriterCommand::Shutdown { reply_tx };
        loop {
            match self.queue_tx.try_send(command) {
                Ok(()) => break,
                Err(TrySendError::Full(returned)) => {
                    if Instant::now() >= enqueue_deadline {
                        self.hard_stop();
                        return;
                    }
                    command = returned;
                    thread::sleep(SHUTDOWN_QUEUE_RETRY_INTERVAL);
                }
                Err(TrySendError::Disconnected(_)) => {
                    self.stop_requested.store(true, Ordering::Release);
                    return;
                }
            }
        }

        match reply_rx.recv_timeout(SHUTDOWN_FLUSH_TIMEOUT) {
            Ok(_) => {
                self.stop_requested.store(true, Ordering::Release);
            }
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                self.hard_stop();
            }
        }
    }

    fn begin_management(&self) -> std::result::Result<(), String> {
        if !self.accepting_records.load(Ordering::Acquire)
            || self.stop_requested.load(Ordering::Acquire)
        {
            return Err("query_recorder is stopping".to_string());
        }
        if self.writer_recovering.load(Ordering::Acquire) {
            return Err("query_recorder storage is recovering".to_string());
        }
        if self
            .management_inflight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err("query_recorder management operation already in progress".to_string());
        }
        if !self.accepting_records.load(Ordering::Acquire)
            || self.stop_requested.load(Ordering::Acquire)
            || self.writer_recovering.load(Ordering::Acquire)
        {
            self.management_inflight.store(false, Ordering::Release);
            return Err("query_recorder storage is unavailable".to_string());
        }
        Ok(())
    }

    fn wait_management<T>(
        &self,
        started_rx: ReplyReceiver<()>,
        reply_rx: ReplyReceiver<std::result::Result<T, String>>,
        cancelled: &Arc<AtomicBool>,
    ) -> std::result::Result<T, String> {
        match started_rx.recv_timeout(MANAGEMENT_START_TIMEOUT) {
            Ok(()) => {}
            Err(RecvTimeoutError::Timeout) => {
                cancelled.store(true, Ordering::Release);
                return Err("query_recorder management request start timed out".to_string());
            }
            Err(RecvTimeoutError::Disconnected) => {
                self.management_inflight.store(false, Ordering::Release);
                return Err("query_recorder writer became unavailable".to_string());
            }
        }
        match reply_rx.recv_timeout(MANAGEMENT_OPERATION_TIMEOUT) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => {
                cancelled.store(true, Ordering::Release);
                self.writer_interrupt.interrupt();
                Err("query_recorder management operation timed out".to_string())
            }
            Err(RecvTimeoutError::Disconnected) => {
                self.management_inflight.store(false, Ordering::Release);
                Err("query_recorder writer became unavailable".to_string())
            }
        }
    }

    pub(super) fn drop_oversized_record(&self) {
        self.record_drop(DropKind::Oversized);
    }

    fn record_drop(&self, kind: DropKind) {
        self.dropped_total.fetch_add(1, Ordering::Relaxed);
        match kind {
            DropKind::QueueFull => {
                self.drop_queue_full.fetch_add(1, Ordering::Relaxed);
            }
            DropKind::WriterDisconnected => {
                self.drop_writer_disconnected
                    .fetch_add(1, Ordering::Relaxed);
            }
            DropKind::Oversized => {
                self.drop_oversized.fetch_add(1, Ordering::Relaxed);
            }
        }

        let now = Instant::now();
        let mut state = match self.drop_log_state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        };
        let should_warn = match state.last_warn {
            Some(last_warn) => now.duration_since(last_warn) >= DROP_WARN_INTERVAL,
            None => true,
        };
        if !should_warn {
            return;
        }
        state.last_warn = Some(now);
        drop(state);

        let queue_full = self.drop_queue_full.swap(0, Ordering::Relaxed);
        let writer_disconnected = self.drop_writer_disconnected.swap(0, Ordering::Relaxed);
        let oversized = self.drop_oversized.swap(0, Ordering::Relaxed);
        warn!(
            query_recorder_tag = %self.tag,
            queue_full,
            writer_disconnected,
            oversized,
            "query_recorder dropped records"
        );
    }

    pub(super) fn cleanup(&self, cutoff_ms: i64) -> CleanupReply {
        self.begin_management()?;
        let started = Instant::now();
        let cancelled = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        let command = WriterCommand::Cleanup {
            cutoff_ms,
            started_tx,
            reply_tx,
            cancelled: cancelled.clone(),
        };
        match self.queue_tx.try_send(command) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.management_inflight.store(false, Ordering::Release);
                return Err("query_recorder writer queue is busy".to_string());
            }
            Err(TrySendError::Disconnected(_)) => {
                self.management_inflight.store(false, Ordering::Release);
                return Err("query_recorder writer is unavailable".to_string());
            }
        }
        let result = self.wait_management(started_rx, reply_rx, &cancelled);
        if let Ok(result) = &result {
            log_space_reclaim(
                &self.tag,
                "periodic",
                result.deleted_records,
                &result.space,
                started.elapsed(),
            );
        }
        result
    }

    pub(super) fn clear_history(&self) -> ClearHistoryReply {
        self.begin_management()?;
        let started = Instant::now();
        let cancelled = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        let command = WriterCommand::ClearHistory {
            started_tx,
            reply_tx,
            cancelled: cancelled.clone(),
        };
        match self.queue_tx.try_send(command) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.management_inflight.store(false, Ordering::Release);
                return Err("query_recorder writer queue is busy".to_string());
            }
            Err(TrySendError::Disconnected(_)) => {
                self.management_inflight.store(false, Ordering::Release);
                return Err("query_recorder writer is unavailable".to_string());
            }
        }
        let result = self.wait_management(started_rx, reply_rx, &cancelled);
        if let Ok(result) = &result {
            log_space_reclaim(
                &self.tag,
                "manual",
                result.cleared_records,
                &result.space,
                started.elapsed(),
            );
        }
        result
    }

    #[cfg(test)]
    pub(super) fn flush_for_test(&self) -> FlushReply {
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        self.queue_tx
            .send(WriterCommand::Flush { reply_tx })
            .map_err(|err| format!("query_recorder flush enqueue failed: {err}"))?;
        reply_rx
            .recv()
            .map_err(|err| format!("query_recorder flush reply failed: {err}"))?
    }

    #[cfg(test)]
    pub(super) fn set_recovering_for_test(&self, recovering: bool) {
        self.writer_recovering.store(recovering, Ordering::Release);
    }
}

fn log_space_reclaim(
    tag: &str,
    operation: &str,
    deleted_records: usize,
    space: &SpaceReclaimResult,
    elapsed: Duration,
) {
    info!(
        query_recorder_tag = tag,
        operation,
        deleted_records,
        migrated = space.migrated,
        auto_vacuum_before = space.reclaimable.auto_vacuum,
        auto_vacuum_after = space.after.auto_vacuum,
        page_size = space.after.page_size,
        page_count_before = space.before.page_count,
        page_count_reclaimable = space.reclaimable.page_count,
        page_count_after = space.after.page_count,
        freelist_before = space.before.freelist_count,
        freelist_reclaimable = space.reclaimable.freelist_count,
        freelist_after = space.after.freelist_count,
        database_bytes_before = space.before.database_bytes,
        database_bytes_after = space.after.database_bytes,
        wal_bytes_before = space.before.wal_bytes,
        wal_bytes_peak = space.peak_wal_bytes,
        wal_bytes_after = space.after.wal_bytes,
        reclaimed_bytes = space.reclaimed_bytes(),
        elapsed_ms = elapsed.as_millis(),
        "query_recorder space reclaim completed"
    );
}
