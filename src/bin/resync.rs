#![allow(clippy::field_reassign_with_default)]

use std::env;
use std::path::PathBuf;

use getopts::Options;
use log::*;

use resync::*;

#[derive(Default)]
struct Config {
    verbosity: usize,
    wait: u64,
    user: String,
    host: String,
    port: u16,
    accept_host_key: bool,
    local_file: PathBuf,
    remote_path: PathBuf,
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
        .module("resync")
        .verbosity(config.verbosity)
        .init()
        .unwrap();

    /*
    let mut session = match connect(&config.host, config.port, &config.user) {
        Ok(s) => s,
        Err(e) => {
            error!("cannot connect to {}: {}", config.host, e);
            return;
        }
    };
    */
    let mut resync = match Resync::new(config.host.clone(), config.port, config.user.clone())
        .connect(config.accept_host_key)
    {
        Ok(r) => {
            debug!("connected");
            r
        }
        Err(e) => {
            error!("can't connect to {}: {}", config.host, e);
            std::process::exit(1);
        }
    };

    info!("connected to {}.", config.host);

    if let Err(e) = resync.watch(config.local_file, config.remote_path, config.wait) {
        error!("error during operation: {}", e);
        std::process::exit(1);
    }
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
    opts.optflag(
        "",
        "accept",
        "Automatically accept host keys for unknown hosts",
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
    config.accept_host_key = matches.opt_present("accept");
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

    config.local_file = PathBuf::from(&matches.free[0]);

    let remote: Vec<&str> = matches.free[1].split(':').collect();
    if remote.len() != 2 {
        return Err(Error::Config(
            "remote should be in the form host:remote_path".to_string(),
        ));
    }

    config.host = remote[0].to_string();
    let rpath = remote[1].to_string();

    config.remote_path = if rpath.ends_with('/') {
        let filename = config
            .local_file
            .file_name()
            .expect("no filename for local file?");
        let mut rpath = PathBuf::from(&rpath);
        rpath.push(filename);
        rpath
    } else {
        PathBuf::from(&config.remote_path)
    };

    Ok(config)
}
