//! BitAiir node library.
//!
//! This crate is the integration layer: it loads configuration, opens the
//! storage, starts the chain state machine, brings up the P2P listener, and
//! mounts the RPC server. The `bitaiir-daemon` binary is a thin wrapper that
//! parses CLI flags and calls into this library.
//!
//! Splitting this into a library (rather than putting everything in the
//! daemon binary) lets integration tests spin up a full in-process node and
//! lets us, in the future, embed a node inside other processes.

#![forbid(unsafe_code)]
