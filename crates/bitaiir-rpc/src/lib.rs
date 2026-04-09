//! JSON-RPC interface to a running BitAiir node.
//!
//! This crate hosts the JSON-RPC server consumed by `bitaiir-cli` (and any
//! third-party tooling) and the request/response type definitions shared
//! between server and client. The method shape mirrors `bitcoind`'s RPC where
//! it makes sense — `getblockchaininfo`, `getbalance`, `sendtoaddress`,
//! `getnewaddress`, `generatetoaddress`, etc. — so existing tooling and
//! mental models carry over.

#![forbid(unsafe_code)]
