//! Wire protocol: message framing with magic bytes and checksums.
//!
//! Every P2P message is framed as:
//!
//! ```text
//! +---------+---------+---------+---------+---------+
//! | magic   | command | length  | checksum| payload |
//! | 4 bytes | 12 bytes| 4 bytes | 4 bytes | N bytes |
//! +---------+---------+---------+---------+---------+
//! ```
//!
//! - magic: `0xB1 0x7A 0x11 0xED` (BitAiir network identifier)
//! - command: ASCII string padded with null bytes to 12 bytes
//! - length: payload length as little-endian u32
//! - checksum: first 4 bytes of double_sha256(payload)
//! - payload: serialized message data

use bitaiir_crypto::hash::double_sha256;
use bitaiir_types::Network;

/// Network magic bytes (protocol §10.1) for the currently-active
/// network.  Mainnet and testnet use distinct magic bytes so nodes
/// on different networks cannot accidentally peer with each other
/// — a stray connection will fail at the first header parse.
#[inline]
pub fn magic() -> [u8; 4] {
    Network::active().magic()
}

/// Total size of a message header (before the payload).
pub const HEADER_SIZE: usize = 4 + 12 + 4 + 4; // 24 bytes

/// Maximum payload size (1 MB, matching MAX_BLOCK_SIZE).
pub const MAX_PAYLOAD_SIZE: u32 = 1_000_000;

/// Encode a command string into a 12-byte null-padded array.
pub fn encode_command(cmd: &str) -> [u8; 12] {
    let mut buf = [0u8; 12];
    let bytes = cmd.as_bytes();
    let len = bytes.len().min(12);
    buf[..len].copy_from_slice(&bytes[..len]);
    buf
}

/// Decode a 12-byte null-padded command into a string.
pub fn decode_command(buf: &[u8; 12]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(12);
    String::from_utf8_lossy(&buf[..end]).to_string()
}

/// Compute the 4-byte checksum of a payload.
pub fn checksum(payload: &[u8]) -> [u8; 4] {
    let hash = double_sha256(payload);
    [hash[0], hash[1], hash[2], hash[3]]
}

/// Build a complete framed message (header + payload).
pub fn frame_message(command: &str, payload: &[u8]) -> Vec<u8> {
    let cmd = encode_command(command);
    let len = (payload.len() as u32).to_le_bytes();
    let cs = checksum(payload);

    let mut msg = Vec::with_capacity(HEADER_SIZE + payload.len());
    msg.extend_from_slice(&magic());
    msg.extend_from_slice(&cmd);
    msg.extend_from_slice(&len);
    msg.extend_from_slice(&cs);
    msg.extend_from_slice(payload);
    msg
}

/// Parsed message header.
#[derive(Debug, Clone)]
pub struct MessageHeader {
    pub command: String,
    pub payload_len: u32,
    pub checksum: [u8; 4],
}

/// Parse a 24-byte header. Returns None if magic doesn't match.
pub fn parse_header(buf: &[u8; HEADER_SIZE]) -> Option<MessageHeader> {
    if buf[..4] != magic() {
        return None;
    }
    let mut cmd_buf = [0u8; 12];
    cmd_buf.copy_from_slice(&buf[4..16]);

    let payload_len = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
    let checksum = [buf[20], buf[21], buf[22], buf[23]];

    Some(MessageHeader {
        command: decode_command(&cmd_buf),
        payload_len,
        checksum,
    })
}
