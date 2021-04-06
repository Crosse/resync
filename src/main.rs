#![allow(clippy::field_reassign_with_default)]

use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::path::Path;
use std::sync::mpsc::channel;
use std::time::{Duration, Instant};
use std::{env, io};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use bytesize::ByteSize;
use getopts::Options;
use log::*;
use notify::{watcher, DebouncedEvent, RecursiveMode, Watcher};
use ssh2::KnownHostFileKind;
use ssh2::{CheckResult, HashType, Prompt, Session};
use termion::input::TermRead;

mod errors;
use crate::errors::*;

#[derive(Default)]
struct Config {
    verbosity: usize,
    wait: u64,
    user: String,
    host: String,
    port: u16,
    local_file: String,
    remote_path: String,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let config = match parse_args(&program, args) {
        Ok(c) => c,
        Err(e) => {
            error!("error: {}", e);
            std::process::exit(1);
        }
    };

    stderrlog::new()
        .module(module_path!())
        .verbosity(config.verbosity)
        .init()
        .unwrap();

    let mut session = match connect(&config.host, config.port, &config.user) {
        Ok(s) => s,
        Err(e) => {
            error!("cannot connect to {}: {}", config.host, e);
            return;
        }
    };

    if session.authenticated() {
        debug!("authenticated");
    } else {
        error!("all authentication methods failed");
        std::process::exit(1);
    }

    info!("connected to {}.", config.host);

    if let Err(e) = resync(&mut session, &config.local_file, &config.remote_path) {
        error!("error during initial sync: {}", e);
        std::process::exit(1);
    }

    if let Err(e) = watch(
        &mut session,
        &config.local_file,
        &config.remote_path,
        config.wait,
    ) {
        error!("error during operation: {}", e);
        std::process::exit(1);
    }
}

fn watch(session: &mut Session, local_file: &str, remote_path: &str, wait: u64) -> Result<()> {
    // XXX: verify local_file is a single file, for now!

    info!("watching local file for changes");
    let (tx, rx) = channel();
    let mut watcher = watcher(tx, Duration::from_secs(wait))?;
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
                    debug!("successfully rewatched {}", local_file);
                    resync(session, local_file, remote_path)?;
                }
                Write(_) | Create(_) => {
                    resync(session, local_file, remote_path)?;
                }
                _ => debug!("received ignored event {:?}", event),
            },
            Err(e) => return Err(e.into()),
        }
    }
}

fn resync(session: &mut Session, local_file: &str, remote_path: &str) -> Result<()> {
    info!("resyncing {} => {}", local_file, remote_path);

    let lpath = Path::new(local_file);
    let mut lfile = File::open(lpath)?;
    let lmeta = lfile.metadata()?;
    debug!("found local file");

    let perms = if cfg!(unix) {
        lmeta.permissions().mode() & 0x00ff
    } else {
        0o644
    };

    let rpath = Path::new(remote_path);
    // TODO: at some point transfer the mtime and atime.
    let mut rfile = session.scp_send(rpath, perms as i32, lmeta.len(), None)?;

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
        local_file, remote_path, end, bs
    );

    Ok(())
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options] FILE HOST:REMOTE_PATH", program);
    print!("{}", opts.usage(&brief));
}

fn parse_args(program: &str, args: Vec<String>) -> Result<Config> {
    let mut opts = Options::new();
    opts.optflag("h", "help", "Prints this usage information");
    opts.optopt(
        "l",
        "",
        "Specifies the user to log in as on the remote machine",
        "login_name",
    );
    opts.optopt("p", "", "Port to connect to on the remote host", "port");
    opts.optflagmulti("v", "verbose", "Be more verbose");
    opts.optopt(
        "w",
        "wait",
        "The amount of time to wait before resyncing a changed file",
        "sec",
    );

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            return Err(Error::Config(format!("{}", f)));
        }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        std::process::exit(0);
    }

    if matches.free.len() < 2 {
        print_usage(&program, opts);
        return Err(Error::Config("not enough arguments".to_string()));
    }

    let mut config = Config::default();

    // start verbosity at INFO
    config.verbosity = matches.opt_count("v") + 2;
    config.wait = match matches.opt_get_default("w", 1) {
        Ok(w) => w,
        Err(e) => return Err(Error::Config(format!("invalid value for 'wait': {}", e))),
    };

    config.user = match matches.opt_str("l") {
        Some(l) => l,
        None => match env::var("USER") {
            Ok(u) => u,
            Err(_) => {
                return Err(Error::Config(
                    "user (-l) not specified, and $USER not set".to_string(),
                ))
            }
        },
    };

    config.port = match matches.opt_get_default("p", 22) {
        Ok(p) => p,
        Err(e) => return Err(Error::Config(format!("invalid value for 'port': {}", e))),
    };

    config.local_file = matches.free[0].clone();

    let remote: Vec<&str> = matches.free[1].split(':').collect();
    if remote.len() != 2 {
        return Err(Error::Config(
            "remote should be in the form host:remote_path".to_string(),
        ));
    }

    config.host = remote[0].to_string();
    config.remote_path = remote[1].to_string();

    Ok(config)
}

fn connect(host: &str, port: u16, user: &str) -> Result<Session> {
    let tcp = TcpStream::connect(format!("{}:{}", host, port))?;
    let mut session = Session::new()?;
    session.set_tcp_stream(tcp);
    session.handshake()?;

    check_known_host(&session, host)?;

    let methods = match session.auth_methods(user) {
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
                if session.userauth_agent(user).is_ok() {
                    return Ok(session);
                }
            }
            "keyboard-interactive" => {
                debug!("trying keyboard interactive auth");
                let mut prompter = KeyboardInteractivePrompt {};
                if session
                    .userauth_keyboard_interactive(user, &mut prompter)
                    .is_ok()
                {
                    return Ok(session);
                }
            }
            "password" => {
                for _ in 0..3 {
                    if let Some(pw) = get_password(user, host) {
                        if session.userauth_password(user, &pw).is_ok() {
                            return Ok(session);
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

fn check_known_host(session: &Session, host: &str) -> Result<()> {
    let mut known_hosts = session.known_hosts().unwrap();

    let file = Path::new(&env::var("HOME").unwrap()).join(".ssh/known_hosts");
    known_hosts
        .read_file(&file, KnownHostFileKind::OpenSSH)
        .unwrap();

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

    let resp = get_response(
        "Are you sure you want to continue connecting (yes/no)? ",
        false,
    );

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
