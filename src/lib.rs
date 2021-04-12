use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::mpsc::channel;
use std::time::{Duration, Instant};
use std::{env, io};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use bytesize::ByteSize;
use log::*;
use notify::{watcher, DebouncedEvent, RecursiveMode, Watcher};
use ssh2::KnownHostFileKind;
use ssh2::{CheckResult, HashType, Prompt, Session};
use termion::input::TermRead;

mod errors;
pub use crate::errors::*;

/// Describes the connection state of a [`Resync`] struct.
///
/// This trait is sealed and cannot be implemented for types outside of `resync`.
pub trait ConnectionState: private::Sealed {}

/// Describes a [`Resync`] that is connected to a host.
pub struct Connected {
    session: Session,
}

impl ConnectionState for Connected {}

/// Describes a [`Resync`] that is not connected to a host.
pub struct Disconnected;
impl ConnectionState for Disconnected {}

struct State {
    remote_host: String,
    port: u16,
    username: String,
    timeout: u32,
}

/// [`Resync`] takes care of connecting to a remote host via SSH, watching a
/// local file, and copying that file to the remote host when it changes.
pub struct Resync<S: ConnectionState> {
    state: Box<State>,
    extra: S,
}

impl Resync<Disconnected> {
    /// Create a new [`Resync`] in a disconnected state.
    pub fn new(remote_host: String, port: u16, username: String) -> Self {
        Self {
            state: Box::new(State {
                remote_host,
                port,
                username,
                timeout: 30 * 1000,
            }),
            extra: Disconnected {},
        }
    }

    /// Connects to the remote host via SSH.
    ///
    /// `connect()` will attempt to authenticate using one of the following
    /// methods, in the order preferred by the server:
    ///
    /// - publickey
    /// - password
    /// - keyboard-interactive
    pub fn connect(self, accept_host_key: bool) -> Result<Resync<Connected>> {
        let state = &self.state;
        debug!(
            "attempting to connect to {}:{}",
            state.remote_host, state.port
        );

        let tcp = TcpStream::connect(format!("{}:{}", state.remote_host, state.port))?;
        let mut session = Session::new()?;
        debug!("connected.");

        debug!("setting up SSH session");
        session.set_tcp_stream(tcp);
        session.set_timeout(state.timeout);
        session.handshake()?;

        check_known_host(&session, &state.remote_host, accept_host_key)?;

        let methods = match session.auth_methods(&state.username) {
            Ok(m) => m,
            Err(e) => {
                if session.authenticated() {
                    error!("SSH_USERAUTH_NONE succeeded, which should never happen");
                } else {
                    error!("SSH_USERAUTH_NONE failed: {}", e);
                }
                return Err(Error::AuthFailed);
            }
        };
        debug!("auth methods supported by host: {}", methods);

        let methods = methods.split(',').collect::<Vec<&str>>();

        for method in methods {
            match method {
                "publickey" => {
                    debug!("trying publickey auth");
                    if session.userauth_agent(&state.username).is_ok() && session.authenticated() {
                        return Ok(Resync {
                            state: self.state,
                            extra: Connected { session },
                        });
                    }
                }
                "keyboard-interactive" => {
                    debug!("trying keyboard interactive auth");
                    let mut prompter = KeyboardInteractivePrompt {};
                    if session
                        .userauth_keyboard_interactive(&state.username, &mut prompter)
                        .is_ok()
                        && session.authenticated()
                    {
                        return Ok(Resync {
                            state: self.state,
                            extra: Connected { session },
                        });
                    }
                }
                "password" => {
                    for _ in 0..3 {
                        if let Some(pw) = get_password(&state.username, &state.remote_host) {
                            if session.userauth_password(&state.username, &pw).is_ok()
                                && session.authenticated()
                            {
                                return Ok(Resync {
                                    state: self.state,
                                    extra: Connected { session },
                                });
                            } else {
                                warn!("Permission denied, please try again.");
                            }
                        }
                    }
                }
                _ => debug!("skipping unhandled auth method {}", method),
            }
        }

        Err(Error::AuthFailed)
    }
}

impl Resync<Connected> {
    /// Starts watching a local file for changes, and copies it to the remote host.
    ///
    /// `delay` tells the watcher how long to wait before sending change
    /// notifications. This can be used, for instance, if the file being watched
    /// gets modified by multiple things in succession, and you want to make sure
    /// that only the final result gets copied.
    ///
    /// `watch()` will unconditionally copy the watched file to the remote host before
    /// it starts watching for changes.
    pub fn watch<T: AsRef<Path>>(
        &mut self,
        local_file: T,
        remote_path: T,
        delay: u64,
    ) -> Result<()> {
        let local_file = local_file.as_ref();
        let remote_path = remote_path.as_ref();

        if !local_file.is_file() {
            return Err(Error::NotAFile(local_file.display().to_string()));
        }

        self.resync(local_file, remote_path)?;

        info!("watching local file for changes");
        let (tx, rx) = channel();
        let mut watcher = watcher(tx, Duration::from_secs(delay))?;
        watcher.watch(local_file, RecursiveMode::NonRecursive)?;

        loop {
            use DebouncedEvent::*;
            match rx.recv() {
                Ok(event) => match event {
                    NoticeRemove(ref p) => {
                        watcher.unwatch(p)?;
                        while let Err(notify::Error::PathNotFound) =
                            watcher.watch(p, RecursiveMode::NonRecursive)
                        {
                            warn!("path vanished; waiting for it to return");
                            std::thread::sleep(Duration::from_secs(1));
                        }
                        debug!("successfully rewatched {}", local_file.display());
                        self.resync(local_file, remote_path)?;
                    }
                    Write(_) | Create(_) => {
                        self.resync(local_file, remote_path)?;
                    }
                    _ => debug!("received ignored event {:?}", event),
                },
                Err(e) => return Err(e.into()),
            }
        }
    }

    fn resync<T: AsRef<Path>>(&self, local_file: T, remote_path: T) -> Result<()> {
        let local_file = local_file.as_ref();
        let remote_path = remote_path.as_ref();

        let mut lfile = File::open(local_file)?;
        let lmeta = lfile.metadata()?;
        debug!("found local file {}", local_file.display());

        info!(
            "resyncing {} => {}",
            local_file.display(),
            remote_path.display()
        );

        let perms = if cfg!(unix) {
            lmeta.permissions().mode() & 0x00ff
        } else {
            0o644
        };

        // TODO: at some point transfer the mtime and atime.
        let mut rfile =
            self.extra
                .session
                .scp_send(&remote_path, perms as i32, lmeta.len(), None)?;

        let mut count = 0;
        let mut buf = [0u8; 4096];

        let start = Instant::now();
        while let Ok(b) = lfile.read(&mut buf) {
            if b == 0 {
                trace!("zero-byte read");
                break;
            }
            match rfile.write(&buf[0..b]) {
                Ok(written) => {
                    trace!("wrote {} bytes", written);
                    count += written;
                    if written != b {
                        error!("short write: {} read != {} written", b, written);
                        break;
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
        let end = start.elapsed().as_secs_f32();
        let bps = (count as f32) / end;
        let bs = ByteSize::b(bps as u64);

        info!(
            "{} => {} in {:.2}s ({}/s)",
            local_file.display(),
            remote_path.display(),
            end,
            bs
        );

        Ok(())
    }
}

fn get_response(question: &str, sensitive: bool) -> Option<String> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    let stdin = io::stdin();
    let mut stdin = stdin.lock();

    write!(stdout, "{}", question).unwrap();
    stdout.flush().unwrap();

    let response = if sensitive {
        let r = stdin.read_passwd(&mut stdout);
        writeln!(stdout).unwrap();
        r
    } else {
        stdin.read_line()
    };

    stdout.flush().unwrap();

    if let Ok(Some(resp)) = response {
        return Some(resp);
    }
    None
}

fn get_password(username: &str, host: &str) -> Option<String> {
    get_response(&format!("{}@{}'s password: ", username, host), true)
}

fn check_known_host(session: &Session, host: &str, accept_host_key: bool) -> Result<()> {
    let mut known_hosts = session.known_hosts().unwrap();

    let file = Path::new(&env::var("HOME").unwrap()).join(".ssh/known_hosts");
    known_hosts
        .read_file(&file, KnownHostFileKind::OpenSSH)
        .unwrap();

    debug!("checking host key");
    let (key, key_type) = session.host_key().unwrap();
    match known_hosts.check(host, key) {
        CheckResult::Match => return Ok(()),
        CheckResult::NotFound => {}
        CheckResult::Mismatch => return Err(Error::HostKeyValidationFailed),
        CheckResult::Failure => {
            debug!("an error occurred while checking for host keys");
            return Err(Error::HostKeyValidationFailed);
        }
    }

    println!("The authenticity of host '{}' can't be established.", host);
    println!(
        "{:?} key fingerprint is SHA256:{}.",
        key_type,
        base64::encode(session.host_key_hash(HashType::Sha256).unwrap()).trim_end_matches('=')
    );

    let resp = if accept_host_key {
        get_response(
            "Are you sure you want to continue connecting (yes/no)? ",
            false,
        )
    } else {
        Some("yes".to_string())
    };

    if let Some(r) = resp {
        if r == "yes" {
            known_hosts.add(host, key, host, key_type.into()).unwrap();
            known_hosts.write_file(&file, KnownHostFileKind::OpenSSH)?;
            println!(
                "Warning: Permanently added '{}' ({:?}) to the list of known hosts.",
                host, key_type
            );
            return Ok(());
        }
    }

    Err(Error::HostKeyValidationFailed)
}

struct KeyboardInteractivePrompt {}

impl ssh2::KeyboardInteractivePrompt for KeyboardInteractivePrompt {
    fn prompt<'a>(
        &mut self,
        username: &str,
        instructions: &str,
        prompts: &[Prompt<'a>],
    ) -> Vec<String> {
        let stdout = io::stdout();
        let mut stdout = stdout.lock();
        let stdin = io::stdin();
        let mut stdin = stdin.lock();

        writeln!(stdout, "username: {}", username).unwrap();
        writeln!(stdout, "{}", instructions).unwrap();
        stdout.flush().unwrap();

        let mut responses = Vec::<String>::new();

        for prompt in prompts {
            write!(stdout, "{}: ", prompt.text).unwrap();

            let response = if prompt.echo {
                stdin.read_line()
            } else {
                stdin.read_passwd(&mut stdout)
            };
            writeln!(stdout).unwrap();
            stdout.flush().unwrap();

            if let Ok(Some(resp)) = response {
                responses.push(resp);
            } else {
                write!(stdout, "error reading from stdin").unwrap();
                stdout.flush().unwrap();

                return responses;
            }
        }

        responses
    }
}

mod private {
    pub trait Sealed {}

    impl Sealed for super::Connected {}
    impl Sealed for super::Disconnected {}
}
