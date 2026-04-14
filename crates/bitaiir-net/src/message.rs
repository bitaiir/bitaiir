//! P2P message types.
//!
//! Each variant maps to a "command" string in the wire protocol header.
//! Payloads are simple binary: fixed-size fields in order. No bincode
//! here — the wire format is hand-rolled for exact control.

use bitaiir_types::{BlockHeader, encoding};

/// Maximum number of block headers in a single `Headers` message.
/// 2000 matches Bitcoin Core — enough to cover weeks of chain history
/// in one round trip while keeping the payload under 200 KiB.
pub const MAX_HEADERS_PER_MESSAGE: usize = 2000;

/// A P2P network message.
#[derive(Debug, Clone)]
pub enum NetMessage {
    /// First message after TCP connect. Exchanges node info.
    Version(VersionMessage),
    /// Acknowledges a received Version message. Empty payload.
    Verack,
    /// Keepalive request. Carries a random nonce.
    Ping(u64),
    /// Keepalive response. Echoes the nonce from Ping.
    Pong(u64),
    /// Request block **headers** starting *after* the given height.
    /// Used to cheaply validate a chain's proof of work before
    /// committing bandwidth to downloading full block bodies.
    GetHeaders(u64),
    /// A batch of block headers (response to `GetHeaders`).  Capped
    /// at [`MAX_HEADERS_PER_MESSAGE`]; peers request again with a
    /// new `start` to continue.
    Headers(Vec<BlockHeader>),
    /// Request block **bodies** from a given height onward.
    GetBlocks(u64),
    /// A serialized block (canonical bincode bytes).
    BlockData(Vec<u8>),
    /// Signals the end of a block sync stream.
    SyncDone,
    /// A serialized transaction for mempool gossip.
    TxData(Vec<u8>),
    /// Request a list of known peer addresses.
    GetAddr,
    /// A batch of known peer addresses (response to GetAddr, or
    /// periodic relay).  Capped at 1000 entries per message.
    Addr(Vec<PeerAddr>),
}

/// An address entry exchanged via the `addr` / `getaddr` protocol.
#[derive(Debug, Clone)]
pub struct PeerAddr {
    /// Network address as `"ip:port"`.
    pub addr: String,
    /// Bitmask of services the peer offers (1 = full node).
    pub services: u64,
    /// Unix timestamp when this peer was last known to be active.
    pub timestamp: u64,
}

/// Maximum number of peer addresses in a single `Addr` message.
const MAX_ADDR_ENTRIES: usize = 1000;

/// Payload of the `version` message.
#[derive(Debug, Clone)]
pub struct VersionMessage {
    /// Protocol version (currently 1).
    pub protocol_version: u32,
    /// Bitmask of services offered (1 = full node).
    pub services: u64,
    /// Sender's Unix timestamp.
    pub timestamp: u64,
    /// Human-readable client identifier.
    pub user_agent: String,
    /// Sender's best block height.
    pub best_height: u64,
}

impl NetMessage {
    /// Return the command string for this message.
    pub fn command(&self) -> &str {
        match self {
            NetMessage::Version(_) => "version",
            NetMessage::Verack => "verack",
            NetMessage::Ping(_) => "ping",
            NetMessage::Pong(_) => "pong",
            NetMessage::GetHeaders(_) => "getheaders",
            NetMessage::Headers(_) => "headers",
            NetMessage::GetBlocks(_) => "getblocks",
            NetMessage::BlockData(_) => "block",
            NetMessage::SyncDone => "syncdone",
            NetMessage::TxData(_) => "tx",
            NetMessage::GetAddr => "getaddr",
            NetMessage::Addr(_) => "addr",
        }
    }

    /// Serialize the message payload to bytes.
    pub fn to_payload(&self) -> Vec<u8> {
        match self {
            NetMessage::Version(v) => {
                let mut buf = Vec::new();
                buf.extend_from_slice(&v.protocol_version.to_le_bytes());
                buf.extend_from_slice(&v.services.to_le_bytes());
                buf.extend_from_slice(&v.timestamp.to_le_bytes());
                // user_agent: length-prefixed string
                let ua_bytes = v.user_agent.as_bytes();
                buf.extend_from_slice(&(ua_bytes.len() as u32).to_le_bytes());
                buf.extend_from_slice(ua_bytes);
                buf.extend_from_slice(&v.best_height.to_le_bytes());
                buf
            }
            NetMessage::Verack => Vec::new(),
            NetMessage::Ping(nonce) => nonce.to_le_bytes().to_vec(),
            NetMessage::Pong(nonce) => nonce.to_le_bytes().to_vec(),
            NetMessage::GetHeaders(start) => start.to_le_bytes().to_vec(),
            NetMessage::Headers(headers) => {
                // Wire format: count (u16 LE) || [len(u32 LE) || bytes] * count
                // Each header is serialized with the canonical block
                // encoding, so adding fields to `BlockHeader` stays
                // wire-compatible at the framing level.
                let count = headers.len().min(MAX_HEADERS_PER_MESSAGE) as u16;
                let mut buf = Vec::new();
                buf.extend_from_slice(&count.to_le_bytes());
                for h in headers.iter().take(MAX_HEADERS_PER_MESSAGE) {
                    let bytes = encoding::to_bytes(h).expect("header encodes");
                    buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                    buf.extend_from_slice(&bytes);
                }
                buf
            }
            NetMessage::GetBlocks(start) => start.to_le_bytes().to_vec(),
            NetMessage::BlockData(bytes) => bytes.clone(),
            NetMessage::SyncDone => Vec::new(),
            NetMessage::TxData(bytes) => bytes.clone(),
            NetMessage::GetAddr => Vec::new(),
            NetMessage::Addr(peers) => {
                let count = peers.len().min(MAX_ADDR_ENTRIES) as u32;
                let mut buf = Vec::new();
                buf.extend_from_slice(&count.to_le_bytes());
                for p in peers.iter().take(MAX_ADDR_ENTRIES) {
                    let addr_bytes = p.addr.as_bytes();
                    buf.extend_from_slice(&(addr_bytes.len() as u16).to_le_bytes());
                    buf.extend_from_slice(addr_bytes);
                    buf.extend_from_slice(&p.services.to_le_bytes());
                    buf.extend_from_slice(&p.timestamp.to_le_bytes());
                }
                buf
            }
        }
    }

    /// Deserialize a message from its command string and payload bytes.
    pub fn from_payload(command: &str, payload: &[u8]) -> Option<Self> {
        match command {
            "version" => {
                if payload.len() < 28 {
                    return None;
                }
                let protocol_version = u32::from_le_bytes(payload[0..4].try_into().ok()?);
                let services = u64::from_le_bytes(payload[4..12].try_into().ok()?);
                let timestamp = u64::from_le_bytes(payload[12..20].try_into().ok()?);
                let ua_len = u32::from_le_bytes(payload[20..24].try_into().ok()?) as usize;
                if payload.len() < 24 + ua_len + 8 {
                    return None;
                }
                let user_agent = String::from_utf8_lossy(&payload[24..24 + ua_len]).to_string();
                let best_height =
                    u64::from_le_bytes(payload[24 + ua_len..32 + ua_len].try_into().ok()?);
                Some(NetMessage::Version(VersionMessage {
                    protocol_version,
                    services,
                    timestamp,
                    user_agent,
                    best_height,
                }))
            }
            "verack" => Some(NetMessage::Verack),
            "ping" => {
                let nonce = u64::from_le_bytes(payload.get(..8)?.try_into().ok()?);
                Some(NetMessage::Ping(nonce))
            }
            "pong" => {
                let nonce = u64::from_le_bytes(payload.get(..8)?.try_into().ok()?);
                Some(NetMessage::Pong(nonce))
            }
            "getheaders" => {
                let start = u64::from_le_bytes(payload.get(..8)?.try_into().ok()?);
                Some(NetMessage::GetHeaders(start))
            }
            "headers" => {
                if payload.len() < 2 {
                    return None;
                }
                let count = u16::from_le_bytes(payload[0..2].try_into().ok()?) as usize;
                if count > MAX_HEADERS_PER_MESSAGE {
                    return None;
                }
                let mut offset = 2;
                let mut headers = Vec::with_capacity(count);
                for _ in 0..count {
                    if offset + 4 > payload.len() {
                        return None;
                    }
                    let len =
                        u32::from_le_bytes(payload[offset..offset + 4].try_into().ok()?) as usize;
                    offset += 4;
                    if offset + len > payload.len() {
                        return None;
                    }
                    let header: BlockHeader =
                        encoding::from_bytes(&payload[offset..offset + len]).ok()?;
                    offset += len;
                    headers.push(header);
                }
                Some(NetMessage::Headers(headers))
            }
            "getblocks" => {
                let start = u64::from_le_bytes(payload.get(..8)?.try_into().ok()?);
                Some(NetMessage::GetBlocks(start))
            }
            "block" => Some(NetMessage::BlockData(payload.to_vec())),
            "syncdone" => Some(NetMessage::SyncDone),
            "tx" => Some(NetMessage::TxData(payload.to_vec())),
            "getaddr" => Some(NetMessage::GetAddr),
            "addr" => {
                if payload.len() < 4 {
                    return None;
                }
                let count = u32::from_le_bytes(payload[0..4].try_into().ok()?) as usize;
                if count > MAX_ADDR_ENTRIES {
                    return None;
                }
                let mut offset = 4;
                let mut peers = Vec::with_capacity(count);
                for _ in 0..count {
                    if offset + 2 > payload.len() {
                        return None;
                    }
                    let addr_len =
                        u16::from_le_bytes(payload[offset..offset + 2].try_into().ok()?) as usize;
                    offset += 2;
                    if offset + addr_len + 16 > payload.len() {
                        return None;
                    }
                    let addr =
                        String::from_utf8_lossy(&payload[offset..offset + addr_len]).to_string();
                    offset += addr_len;
                    let services = u64::from_le_bytes(payload[offset..offset + 8].try_into().ok()?);
                    offset += 8;
                    let timestamp =
                        u64::from_le_bytes(payload[offset..offset + 8].try_into().ok()?);
                    offset += 8;
                    peers.push(PeerAddr {
                        addr,
                        services,
                        timestamp,
                    });
                }
                Some(NetMessage::Addr(peers))
            }
            _ => None,
        }
    }
}
