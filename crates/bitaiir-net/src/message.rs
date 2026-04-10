//! P2P message types.
//!
//! Each variant maps to a "command" string in the wire protocol header.
//! Payloads are simple binary: fixed-size fields in order. No bincode
//! here — the wire format is hand-rolled for exact control.

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
}

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
            _ => None,
        }
    }
}
