//! Peer-to-peer networking layer for BitAiir.
//!
//! This crate implements the BitAiir wire protocol from scratch, modeled on
//! the Bitcoin Core P2P design: TCP transport, custom message framing with a
//! 4-byte network magic, a `version` / `verack` handshake, and message types
//! for gossiping inventories, fetching blocks and transactions, and keeping
//! connections alive.
//!
//! No external P2P framework (libp2p, etc.) is used. The goal is to fully
//! own the protocol so we can evolve it without fighting an abstraction.

#![forbid(unsafe_code)]
