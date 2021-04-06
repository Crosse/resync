use std::sync::mpsc;
use std::{error, fmt};

#[derive(Debug)]
pub(crate) enum Error {
    Config(String),
    AuthFailed,
    HostKeyValidationFailed,
    IO(std::io::Error),
    SSH(ssh2::Error),
    Notify(notify::Error),
    Mpsc(mpsc::RecvError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Config(e) => write!(f, "{}", e),
            Self::AuthFailed => write!(f, "all authentication methods failed"),
            Self::HostKeyValidationFailed => write!(f, "host key validation failed"),
            Self::IO(e) => e.fmt(f),
            Self::SSH(e) => e.fmt(f),
            Self::Notify(e) => e.fmt(f),
            Self::Mpsc(e) => e.fmt(f),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Config(_) => None,
            Self::AuthFailed => None,
            Self::HostKeyValidationFailed => None,
            Self::IO(ref e) => Some(e),
            Self::SSH(ref e) => Some(e),
            Self::Notify(ref e) => Some(e),
            Self::Mpsc(ref e) => Some(e),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::IO(err)
    }
}

impl From<mpsc::RecvError> for Error {
    fn from(err: mpsc::RecvError) -> Self {
        Self::Mpsc(err)
    }
}

impl From<notify::Error> for Error {
    fn from(err: notify::Error) -> Self {
        Self::Notify(err)
    }
}

impl From<ssh2::Error> for Error {
    fn from(err: ssh2::Error) -> Self {
        Self::SSH(err)
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
