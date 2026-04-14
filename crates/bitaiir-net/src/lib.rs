//! Peer-to-peer networking for BitAiir.
//!
//! This crate implements the BitAiir wire protocol from scratch,
//! modeled on Bitcoin Core's P2P design: TCP transport, custom
//! message framing with 4-byte network magic, a version/verack
//! handshake, and (in later phases) message types for block/tx
//! gossip and chain synchronization.
//!
//! Phase P2P-1 (this commit) covers the foundation:
//! - Wire protocol framing (magic, command, length, checksum)
//! - Message types: version, verack, ping, pong
//! - Peer connection with async read/write
//! - Outbound and inbound handshake

#![forbid(unsafe_code)]

pub mod error;
pub mod message;
pub mod peer;
pub mod protocol;

pub use error::{Error, Result};
pub use message::{NetMessage, PeerAddr, VersionMessage};
pub use peer::Peer;
pub use protocol::magic;
