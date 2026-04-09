//! Persistent storage layer for the BitAiir node.
//!
//! Backed by `redb`, a pure-Rust embedded ACID key-value store. This crate
//! owns the on-disk format for blocks, headers, the UTXO set, peer state, and
//! any chain metadata that must survive a restart.
//!
//! Why redb instead of rocksdb? redb is pure Rust (no C++ build dependency),
//! has good Windows support out of the box, and is sufficient for the
//! throughput we need at this stage. If/when storage becomes a bottleneck the
//! interface defined here can be reimplemented over rocksdb without touching
//! callers.

#![forbid(unsafe_code)]
