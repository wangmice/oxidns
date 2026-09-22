// SPDX-FileCopyrightText: 2025 Sven Shi
// SPDX-License-Identifier: GPL-3.0-or-later

//! Filesystem-triggered provider reloads scoped to one plugin runtime generation.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher, recommended_watcher};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use super::ProviderRuntimeControl;
use crate::infra::error::{DnsError, Result as DnsResult};

const FILE_RELOAD_DEBOUNCE: Duration = Duration::from_millis(500);

type DirtySender = mpsc::Sender<()>;

pub(crate) struct ProviderFileReloadService {
    watcher: Option<RecommendedWatcher>,
    cancel: CancellationToken,
    workers: Vec<JoinHandle<()>>,
}

impl fmt::Debug for ProviderFileReloadService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderFileReloadService")
            .field("active", &self.watcher.is_some())
            .field("workers", &self.workers.len())
            .finish()
    }
}

impl ProviderFileReloadService {
    pub(crate) fn start(
        entries: Vec<(String, Arc<ProviderRuntimeControl>, Vec<PathBuf>)>,
    ) -> DnsResult<Option<Self>> {
        Self::start_with_debounce(entries, FILE_RELOAD_DEBOUNCE)
    }

    fn start_with_debounce(
        entries: Vec<(String, Arc<ProviderRuntimeControl>, Vec<PathBuf>)>,
        debounce: Duration,
    ) -> DnsResult<Option<Self>> {
        let base = std::env::current_dir().map_err(|error| {
            DnsError::runtime(format!(
                "failed to resolve working directory for provider file reload: {error}"
            ))
        })?;

        let mut targets: HashMap<PathBuf, Vec<DirtySender>> = HashMap::new();
        let mut worker_specs = Vec::new();
        let mut watched_dirs = HashSet::new();

        for (tag, control, paths) in entries {
            let mut provider_paths = HashSet::new();
            for path in paths {
                let path = absolute_lexical(&base, &path);
                if !provider_paths.insert(path.clone()) {
                    continue;
                }
                let parent = path.parent().ok_or_else(|| {
                    DnsError::plugin(format!(
                        "provider '{tag}' reload watch path '{}' has no parent directory",
                        path.display()
                    ))
                })?;
                watched_dirs.insert(parent.to_path_buf());
            }
            if provider_paths.is_empty() {
                continue;
            }

            let (tx, rx) = mpsc::channel(1);
            for path in provider_paths {
                targets.entry(path).or_default().push(tx.clone());
            }
            worker_specs.push((tag, control, rx));
        }

        if targets.is_empty() {
            return Ok(None);
        }

        let targets = Arc::new(targets);
        let callback_targets = targets.clone();
        let callback_base = base.clone();
        let mut watcher =
            match recommended_watcher(move |result: notify::Result<Event>| match result {
                Ok(event) => signal_event(&callback_base, &callback_targets, event),
                Err(error) => {
                    error!(
                        %error,
                        "provider file watcher backend error; scheduling full resync"
                    );
                    signal_all(&callback_targets);
                }
            }) {
                Ok(watcher) => watcher,
                Err(error) => {
                    warn!(
                        %error,
                        "provider file watcher is unavailable; automatic rule reload disabled"
                    );
                    return Ok(None);
                }
            };

        let mut active_directories = 0usize;
        for directory in &watched_dirs {
            match watcher.watch(directory, RecursiveMode::NonRecursive) {
                Ok(()) => active_directories += 1,
                Err(error) => warn!(
                    directory = %directory.display(),
                    %error,
                    "failed to watch provider rule directory; automatic reload is unavailable for files in this directory"
                ),
            }
        }
        if active_directories == 0 {
            warn!("no provider rule directories could be watched; automatic rule reload disabled");
            return Ok(None);
        }

        let cancel = CancellationToken::new();
        let workers = worker_specs
            .into_iter()
            .map(|(tag, control, rx)| {
                tokio::spawn(run_provider_worker(
                    tag,
                    control,
                    rx,
                    cancel.child_token(),
                    debounce,
                ))
            })
            .collect::<Vec<_>>();

        info!(
            files = targets.len(),
            directories = active_directories,
            providers = workers.len(),
            debounce_ms = debounce.as_millis(),
            "provider file auto-reload started"
        );

        Ok(Some(Self {
            watcher: Some(watcher),
            cancel,
            workers,
        }))
    }

    pub(crate) async fn shutdown(mut self) {
        // Drop the OS watcher first so no new dirty signals can enter this
        // runtime generation while its providers are being drained.
        drop(self.watcher.take());
        self.cancel.cancel();
        for worker in self.workers {
            if let Err(error) = worker.await
                && !error.is_cancelled()
            {
                warn!(%error, "provider file reload worker failed during shutdown");
            }
        }
    }
}

fn signal_event(base: &Path, targets: &HashMap<PathBuf, Vec<DirtySender>>, event: Event) {
    if matches!(event.kind, EventKind::Access(_)) {
        return;
    }

    for event_path in event.paths {
        let path = absolute_lexical(base, &event_path);
        let Some(senders) = targets.get(&path) else {
            continue;
        };
        for sender in senders {
            signal(sender);
        }
    }
}

fn signal_all(targets: &HashMap<PathBuf, Vec<DirtySender>>) {
    for senders in targets.values() {
        for sender in senders {
            // Duplicate sends are harmless: each provider's channel has
            // capacity one and `signal` treats a full channel as already dirty.
            signal(sender);
        }
    }
}

fn signal(sender: &DirtySender) {
    match sender.try_send(()) {
        Ok(()) | Err(mpsc::error::TrySendError::Full(())) => {}
        Err(mpsc::error::TrySendError::Closed(())) => {
            debug!("provider file reload worker is already closed");
        }
    }
}

async fn run_provider_worker(
    tag: String,
    control: Arc<ProviderRuntimeControl>,
    mut dirty: mpsc::Receiver<()>,
    cancel: CancellationToken,
    debounce_duration: Duration,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            signal = dirty.recv() => {
                if signal.is_none() {
                    return;
                }
            }
        }

        let debounce = tokio::time::sleep(debounce_duration);
        tokio::pin!(debounce);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = &mut debounce => break,
                signal = dirty.recv() => {
                    if signal.is_none() {
                        return;
                    }
                    debounce
                        .as_mut()
                        .reset(tokio::time::Instant::now() + debounce_duration);
                }
            }
        }

        match control.reload_after_current().await {
            Ok(()) => info!(
                provider = %tag,
                "provider automatically reloaded after rule file change"
            ),
            Err(error) => warn!(
                provider = %tag,
                %error,
                "provider automatic rule file reload failed; keeping previous snapshot"
            ),
        }
    }
}

fn absolute_lexical(base: &Path, path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    lexical_normalize(joined)
}

fn lexical_normalize(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push(component.as_os_str());
                }
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use std::any::Any;
    use std::fs;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use tempfile::tempdir;
    use tokio::sync::Notify;

    use super::*;
    use crate::infra::error::Result as DnsResult;
    use crate::plugin::Plugin;
    use crate::plugin::provider::Provider;

    const TEST_DEBOUNCE: Duration = Duration::from_millis(40);
    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    #[derive(Debug)]
    struct ReloadingFileProvider {
        tag: String,
        path: PathBuf,
        attempts: AtomicUsize,
        snapshot: Mutex<String>,
    }

    impl ReloadingFileProvider {
        fn new(tag: &str, path: PathBuf, snapshot: &str) -> Self {
            Self {
                tag: tag.to_string(),
                path,
                attempts: AtomicUsize::new(0),
                snapshot: Mutex::new(snapshot.to_string()),
            }
        }

        fn snapshot(&self) -> String {
            self.snapshot.lock().expect("snapshot lock").clone()
        }
    }

    #[async_trait]
    impl Plugin for ReloadingFileProvider {
        fn tag(&self) -> &str {
            &self.tag
        }
    }

    #[async_trait]
    impl Provider for ReloadingFileProvider {
        fn as_any(&self) -> &dyn Any {
            self
        }

        async fn reload(&self) -> DnsResult<()> {
            self.attempts.fetch_add(1, Ordering::Relaxed);
            let content = fs::read_to_string(&self.path).map_err(|error| {
                DnsError::plugin(format!(
                    "test provider '{}' failed to read '{}': {error}",
                    self.tag,
                    self.path.display()
                ))
            })?;
            let candidate = content.trim();
            if candidate == "invalid" {
                return Err(DnsError::plugin("test provider rejected invalid snapshot"));
            }
            *self.snapshot.lock().expect("snapshot lock") = candidate.to_string();
            Ok(())
        }
    }

    #[derive(Debug)]
    struct BlockingProvider {
        tag: String,
        reloads: AtomicUsize,
        started: Notify,
        release: Notify,
    }

    impl BlockingProvider {
        fn new(tag: &str) -> Self {
            Self {
                tag: tag.to_string(),
                reloads: AtomicUsize::new(0),
                started: Notify::new(),
                release: Notify::new(),
            }
        }
    }

    #[async_trait]
    impl Plugin for BlockingProvider {
        fn tag(&self) -> &str {
            &self.tag
        }
    }

    #[async_trait]
    impl Provider for BlockingProvider {
        fn as_any(&self) -> &dyn Any {
            self
        }

        async fn reload(&self) -> DnsResult<()> {
            let reload = self.reloads.fetch_add(1, Ordering::Relaxed);
            if reload == 0 {
                self.started.notify_one();
                self.release.notified().await;
            }
            Ok(())
        }
    }

    fn reload_entry<P>(
        provider: Arc<P>,
        paths: Vec<PathBuf>,
    ) -> (String, Arc<ProviderRuntimeControl>, Vec<PathBuf>)
    where
        P: Provider + 'static,
    {
        let tag = provider.tag().to_string();
        let provider: Arc<dyn Provider> = provider;
        (tag, Arc::new(ProviderRuntimeControl::new(provider)), paths)
    }

    async fn wait_until(mut predicate: impl FnMut() -> bool, message: &str) {
        tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                if predicate() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {message}"));
    }

    #[test]
    fn lexical_normalization_keeps_stable_file_identity() {
        let base = Path::new("base");
        assert_eq!(
            absolute_lexical(base, Path::new("rules/../rules/cn.txt")),
            PathBuf::from("base/rules/cn.txt")
        );
    }

    #[tokio::test]
    async fn filesystem_reload_keeps_old_snapshot_on_failure_and_recovers() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("rules.txt");
        fs::write(&path, "old\n").expect("initial rules");
        let provider = Arc::new(ReloadingFileProvider::new("rules", path.clone(), "old"));
        let service = ProviderFileReloadService::start_with_debounce(
            vec![reload_entry(provider.clone(), vec![path.clone()])],
            TEST_DEBOUNCE,
        )
        .expect("watcher should start")
        .expect("watcher should be active");

        fs::write(&path, "invalid\n").expect("invalid rules");
        wait_until(
            || provider.attempts.load(Ordering::Relaxed) >= 1,
            "failed automatic reload attempt",
        )
        .await;
        assert_eq!(provider.snapshot(), "old");
        let failed_attempts = provider.attempts.load(Ordering::Relaxed);

        fs::write(&path, "new\n").expect("replacement rules");
        wait_until(|| provider.snapshot() == "new", "recovered snapshot").await;
        assert!(provider.attempts.load(Ordering::Relaxed) > failed_attempts);

        service.shutdown().await;
    }

    #[tokio::test]
    async fn filesystem_reload_recovers_after_delete_and_recreate() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("rules.txt");
        fs::write(&path, "old\n").expect("initial rules");
        let provider = Arc::new(ReloadingFileProvider::new("rules", path.clone(), "old"));
        let service = ProviderFileReloadService::start_with_debounce(
            vec![reload_entry(provider.clone(), vec![path.clone()])],
            TEST_DEBOUNCE,
        )
        .expect("watcher should start")
        .expect("watcher should be active");

        fs::remove_file(&path).expect("remove watched rules");
        wait_until(
            || provider.attempts.load(Ordering::Relaxed) >= 1,
            "reload attempt after watched file removal",
        )
        .await;
        assert_eq!(provider.snapshot(), "old");
        let failed_attempts = provider.attempts.load(Ordering::Relaxed);

        fs::write(&path, "recreated\n").expect("recreate watched rules");
        wait_until(|| provider.snapshot() == "recreated", "recreated snapshot").await;
        assert!(provider.attempts.load(Ordering::Relaxed) > failed_attempts);

        service.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn filesystem_reload_observes_atomic_rename_replacement() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("rules.txt");
        let replacement = directory.path().join("rules.next");
        fs::write(&path, "old\n").expect("initial rules");
        let provider = Arc::new(ReloadingFileProvider::new("rules", path.clone(), "old"));
        let service = ProviderFileReloadService::start_with_debounce(
            vec![reload_entry(provider.clone(), vec![path.clone()])],
            TEST_DEBOUNCE,
        )
        .expect("watcher should start")
        .expect("watcher should be active");

        fs::write(&replacement, "renamed\n").expect("replacement contents");
        fs::rename(&replacement, &path).expect("atomic replacement rename");
        wait_until(|| provider.snapshot() == "renamed", "atomic rename reload").await;

        service.shutdown().await;
    }

    #[tokio::test]
    async fn one_file_change_reloads_all_attached_providers() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("shared.txt");
        fs::write(&path, "old\n").expect("initial rules");
        let first = Arc::new(ReloadingFileProvider::new("first", path.clone(), "old"));
        let second = Arc::new(ReloadingFileProvider::new("second", path.clone(), "old"));
        let service = ProviderFileReloadService::start_with_debounce(
            vec![
                reload_entry(first.clone(), vec![path.clone()]),
                reload_entry(second.clone(), vec![path.clone()]),
            ],
            TEST_DEBOUNCE,
        )
        .expect("watcher should start")
        .expect("watcher should be active");

        fs::write(&path, "shared-new\n").expect("updated shared rules");
        wait_until(
            || first.snapshot() == "shared-new" && second.snapshot() == "shared-new",
            "shared file fan-out reload",
        )
        .await;

        service.shutdown().await;
    }

    #[tokio::test]
    async fn dirty_burst_is_coalesced_by_trailing_debounce() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("rules.txt");
        fs::write(&path, "stable\n").expect("rules");
        let provider = Arc::new(ReloadingFileProvider::new("debounced", path, "stable"));
        let control = reload_entry(provider.clone(), Vec::new()).1;
        let (tx, rx) = mpsc::channel(1);
        let cancel = CancellationToken::new();
        let worker = tokio::spawn(run_provider_worker(
            provider.tag().to_string(),
            control,
            rx,
            cancel.child_token(),
            Duration::from_millis(50),
        ));

        tx.send(()).await.expect("first dirty signal");
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _ = tx.try_send(());
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _ = tx.try_send(());

        wait_until(
            || provider.attempts.load(Ordering::Relaxed) >= 1,
            "debounced reload",
        )
        .await;
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(provider.attempts.load(Ordering::Relaxed), 1);

        cancel.cancel();
        worker.await.expect("worker should stop cleanly");
    }

    #[tokio::test]
    async fn dirty_signal_during_reload_runs_one_follow_up_reload() {
        let provider = Arc::new(BlockingProvider::new("blocking"));
        let control = reload_entry(provider.clone(), Vec::new()).1;
        let (tx, rx) = mpsc::channel(1);
        let cancel = CancellationToken::new();
        let worker = tokio::spawn(run_provider_worker(
            provider.tag().to_string(),
            control,
            rx,
            cancel.child_token(),
            Duration::from_millis(10),
        ));

        tx.send(()).await.expect("first dirty signal");
        tokio::time::timeout(TEST_TIMEOUT, provider.started.notified())
            .await
            .expect("first reload should start");
        tx.try_send(()).expect("follow-up dirty signal should fit");
        provider.release.notify_one();

        wait_until(
            || provider.reloads.load(Ordering::Relaxed) == 2,
            "follow-up reload",
        )
        .await;
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(provider.reloads.load(Ordering::Relaxed), 2);

        cancel.cancel();
        worker.await.expect("worker should stop cleanly");
    }

    #[tokio::test]
    async fn shutdown_waits_for_in_flight_reload_and_stops_future_events() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("rules.txt");
        fs::write(&path, "initial\n").expect("initial rules");
        let provider = Arc::new(BlockingProvider::new("blocking"));
        let service = ProviderFileReloadService::start_with_debounce(
            vec![reload_entry(provider.clone(), vec![path.clone()])],
            TEST_DEBOUNCE,
        )
        .expect("watcher should start")
        .expect("watcher should be active");

        fs::write(&path, "first\n").expect("first update");
        tokio::time::timeout(TEST_TIMEOUT, provider.started.notified())
            .await
            .expect("reload should start");

        let shutdown = service.shutdown();
        tokio::pin!(shutdown);
        tokio::select! {
            _ = &mut shutdown => panic!("shutdown finished before in-flight reload"),
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
        provider.release.notify_one();
        shutdown.await;

        let reloads = provider.reloads.load(Ordering::Relaxed);
        fs::write(&path, "after-shutdown\n").expect("post-shutdown update");
        tokio::time::sleep(TEST_DEBOUNCE * 3).await;
        assert_eq!(provider.reloads.load(Ordering::Relaxed), reloads);
    }
}
