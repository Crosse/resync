use crate::{Error, Result};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

pub(crate) fn run(
    path: &Path,
    delay: Duration,
    mut sync: impl FnMut() -> Result<()>,
) -> Result<()> {
    // Preserve the unconditional initial transfer and propagate its failure before watching.
    sync()?;
    log::info!("watching local file for changes");
    let mut changes = FileChanges::new(path, delay)?;
    loop {
        changes.next()?;
        sync()?;
    }
}

// Keep watching the directory, not the inode: editors commonly replace the file.
pub(crate) struct FileChanges {
    _watcher: RecommendedWatcher,
    target: PathBuf,
    rx: Receiver<notify::Result<Event>>,
    debounce: Debounce,
}

struct Debounce {
    delay: Duration,
    deadline: Option<Instant>,
}

impl Debounce {
    fn event(&mut self, target: &Path, event: notify::Result<Event>, now: Instant) -> Result<()> {
        let event = event?;
        if event.need_rescan()
            || (event.paths.iter().any(|p| p == target)
                && matches!(
                    event.kind,
                    EventKind::Any
                        | EventKind::Create(_)
                        | EventKind::Modify(_)
                        | EventKind::Remove(_)
                ))
        {
            self.deadline = Some(now + self.delay);
        }
        Ok(())
    }

    fn ready(&mut self, now: Instant) -> bool {
        if self.deadline.is_some_and(|deadline| now >= deadline) {
            self.deadline = None;
            true
        } else {
            false
        }
    }
}

impl FileChanges {
    pub(crate) fn new(path: &Path, delay: Duration) -> Result<Self> {
        // Canonicalize the parent only, so a symlink/atomic-save target keeps its name.
        let absolute = std::env::current_dir()?.join(path);
        let target = absolute
            .parent()
            .ok_or_else(|| Error::NotAFile(path.display().to_string()))?
            .canonicalize()?
            .join(
                absolute
                    .file_name()
                    .ok_or_else(|| Error::NotAFile(path.display().to_string()))?,
            );
        let (tx, rx) = channel();
        let mut watcher = notify::recommended_watcher(tx)?;
        watcher.watch(target.parent().unwrap(), RecursiveMode::NonRecursive)?;
        Ok(Self {
            _watcher: watcher,
            target,
            rx,
            debounce: Debounce {
                delay,
                deadline: None,
            },
        })
    }

    pub(crate) fn next(&mut self) -> Result<()> {
        loop {
            let event = match self.debounce.deadline {
                Some(deadline) => match self
                    .rx
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                {
                    Ok(event) => Some(event),
                    Err(RecvTimeoutError::Timeout) => None,
                    Err(RecvTimeoutError::Disconnected) => {
                        return Err(std::sync::mpsc::RecvError.into())
                    }
                },
                None => Some(self.rx.recv()?),
            };
            if let Some(event) = event {
                self.debounce.event(&self.target, event, Instant::now())?;
            } else if self.debounce.ready(Instant::now()) {
                match std::fs::metadata(&self.target) {
                    Ok(meta) if meta.is_file() => return Ok(()),
                    Ok(_) => return Err(Error::NotAFile(self.target.display().to_string())),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        // Removal alone is not a transfer. Creation restarts the quiet window.
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{AccessKind, CreateKind, ModifyKind, RemoveKind, RenameMode};

    fn event(kind: EventKind, path: &Path) -> notify::Result<Event> {
        Ok(Event::new(kind).add_path(path.to_path_buf()))
    }

    #[test]
    fn initial_sync_runs_before_watching_and_propagates_failure() {
        let mut calls = 0;
        let result = run(
            Path::new("/nonexistent-parent-resync/target"),
            Duration::from_secs(60),
            || {
                calls += 1;
                Err(Error::Config("transfer failed".into()))
            },
        );
        assert_eq!(calls, 1);
        assert!(matches!(result, Err(Error::Config(_))));
    }

    #[test]
    fn channel_disconnect_and_backend_errors_reach_caller() {
        let mut changes = FileChanges::new(
            &std::env::temp_dir().join("resync-error-target"),
            Duration::ZERO,
        )
        .unwrap();
        let (tx, rx) = channel();
        changes.rx = rx;
        tx.send(Err(notify::Error::generic("backend failed")))
            .unwrap();
        assert!(matches!(changes.next(), Err(Error::Notify(_))));
        drop(tx);
        assert!(matches!(changes.next(), Err(Error::Mpsc(_))));
        changes.debounce.deadline = Some(Instant::now());
        assert!(matches!(changes.next(), Err(Error::Mpsc(_))));
    }

    #[test]
    fn quiet_window_resets_only_for_relevant_changes() {
        let target = Path::new("/target");
        let start = Instant::now();
        let delay = Duration::from_secs(2);
        let mut debounce = Debounce {
            delay,
            deadline: None,
        };
        for kind in [
            EventKind::Create(CreateKind::File),
            EventKind::Modify(ModifyKind::Data(notify::event::DataChange::Any)),
            EventKind::Remove(RemoveKind::File),
            EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
        ] {
            debounce.event(target, event(kind, target), start).unwrap();
            assert!(!debounce.ready(start + delay / 2));
        }
        debounce
            .event(
                target,
                event(EventKind::Create(CreateKind::File), target),
                start + delay / 2,
            )
            .unwrap();
        debounce
            .event(
                target,
                event(EventKind::Modify(ModifyKind::Any), Path::new("/other")),
                start + delay,
            )
            .unwrap();
        debounce
            .event(
                target,
                event(EventKind::Access(AccessKind::Any), target),
                start + delay,
            )
            .unwrap();
        assert!(!debounce.ready(start + delay));
        assert!(debounce.ready(start + delay + delay / 2));
        assert!(!debounce.ready(start + delay * 2));
    }

    #[test]
    fn watcher_errors_are_propagated_and_rescan_is_relevant() {
        let mut debounce = Debounce {
            delay: Duration::ZERO,
            deadline: None,
        };
        assert!(matches!(
            debounce.event(
                Path::new("/target"),
                Err(notify::Error::generic("backend failed")),
                Instant::now()
            ),
            Err(Error::Notify(_))
        ));
        let mut rescan = Event::new(EventKind::Other);
        rescan.attrs.set_flag(notify::event::Flag::Rescan);
        debounce
            .event(Path::new("/target"), Ok(rescan), Instant::now())
            .unwrap();
        assert!(debounce.ready(Instant::now()));
    }

    #[test]
    fn filesystem_bursts_recreation_and_atomic_replacement() {
        let dir = std::env::temp_dir().join(format!(
            "resync-watch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        let target = dir.join("target");
        std::fs::write(&target, "initial").unwrap();
        let mut changes = FileChanges::new(&target, Duration::from_millis(150)).unwrap();
        let (tx, rx) = channel();
        let worker = std::thread::spawn(move || {
            for _ in 0..4 {
                changes.next().unwrap();
                tx.send(Instant::now()).unwrap();
            }
        });
        std::fs::write(dir.join("other"), "ignored").unwrap();
        assert!(rx.recv_timeout(Duration::from_millis(250)).is_err());
        for i in 0..5 {
            std::fs::write(&target, format!("burst {i}")).unwrap();
            std::thread::sleep(Duration::from_millis(30));
        }
        let last = Instant::now();
        assert!(rx.recv_timeout(Duration::from_millis(70)).is_err());
        assert!(
            rx.recv_timeout(Duration::from_secs(5))
                .unwrap()
                .duration_since(last)
                >= Duration::from_millis(100)
        );
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
        std::fs::remove_file(&target).unwrap();
        assert!(rx.recv_timeout(Duration::from_millis(250)).is_err());
        std::fs::write(&target, "recreated").unwrap();
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        std::fs::write(dir.join("replacement"), "atomic").unwrap();
        std::fs::rename(dir.join("replacement"), &target).unwrap();
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "atomic");
        std::fs::write(&target, "after atomic replacement").unwrap();
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        worker.join().unwrap();
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "after atomic replacement"
        );
    }
}
