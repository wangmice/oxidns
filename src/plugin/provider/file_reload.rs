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
                tokio::spawn(run_provider_worker(tag, control, rx, cancel.child_token()))
            })
            .collect::<Vec<_>>();

        info!(
            files = targets.len(),
            directories = active_directories,
            providers = workers.len(),
            debounce_ms = FILE_RELOAD_DEBOUNCE.as_millis(),
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

        let debounce = tokio::time::sleep(FILE_RELOAD_DEBOUNCE);
        tokio::pin!(debounce);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = &mut debounce => break,
                signal = dirty.recv() => {
                    if signal.is_none() {
                        return;
                    }
                    debounce.as_mut().reset(tokio::time::Instant::now() + FILE_RELOAD_DEBOUNCE);
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
    use super::*;

    #[test]
    fn lexical_normalization_keeps_stable_file_identity() {
        let base = Path::new("base");
        assert_eq!(
            absolute_lexical(base, Path::new("rules/../rules/cn.txt")),
            PathBuf::from("base/rules/cn.txt")
        );
    }
}
