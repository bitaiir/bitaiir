//! Error type for the `bitaiir-net` crate.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol error: {0}")]
    Protocol(String),
}

pub type Result<T> = core::result::Result<T, Error>;
