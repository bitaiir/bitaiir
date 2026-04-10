//! A connected peer: async read/write of framed messages over TCP.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tracing::{debug, info, warn};

use crate::error::{Error, Result};
use crate::message::{NetMessage, VersionMessage};
use crate::protocol::{self, HEADER_SIZE, MAX_PAYLOAD_SIZE};

/// A connected P2P peer.
pub struct Peer {
    pub address: SocketAddr,
    reader: OwnedReadHalf,
    writer: OwnedWriteHalf,
}

impl Peer {
    /// Wrap a newly accepted or connected TCP stream.
    pub fn new(stream: TcpStream, address: SocketAddr) -> Self {
        let (reader, writer) = stream.into_split();
        Self {
            address,
            reader,
            writer,
        }
    }

    /// Send a message to this peer.
    pub async fn send(&mut self, msg: &NetMessage) -> Result<()> {
        let payload = msg.to_payload();
        let frame = protocol::frame_message(msg.command(), &payload);
        self.writer.write_all(&frame).await?;
        self.writer.flush().await?;
        debug!("sent {} to {}", msg.command(), self.address);
        Ok(())
    }

    /// Receive the next message from this peer.
    pub async fn receive(&mut self) -> Result<NetMessage> {
        // Read the 24-byte header.
        let mut header_buf = [0u8; HEADER_SIZE];
        self.reader.read_exact(&mut header_buf).await?;

        let header = protocol::parse_header(&header_buf)
            .ok_or_else(|| Error::Protocol("invalid magic bytes".into()))?;

        if header.payload_len > MAX_PAYLOAD_SIZE {
            return Err(Error::Protocol(format!(
                "payload too large: {} bytes",
                header.payload_len,
            )));
        }

        // Read the payload.
        let mut payload = vec![0u8; header.payload_len as usize];
        if !payload.is_empty() {
            self.reader.read_exact(&mut payload).await?;
        }

        // Verify checksum.
        let expected = protocol::checksum(&payload);
        if expected != header.checksum {
            return Err(Error::Protocol("checksum mismatch".into()));
        }

        // Deserialize.
        NetMessage::from_payload(&header.command, &payload).ok_or_else(|| {
            Error::Protocol(format!("unknown or malformed command: {}", header.command))
        })
    }

    /// Perform the outbound handshake: we send version first, then
    /// wait for their version + verack, then send our verack.
    pub async fn handshake_outbound(&mut self, our_height: u64) -> Result<VersionMessage> {
        let our_version = build_version(our_height);
        self.send(&NetMessage::Version(our_version)).await?;

        // Expect their version.
        let their_version = match self.receive().await? {
            NetMessage::Version(v) => v,
            other => {
                return Err(Error::Protocol(format!(
                    "expected version, got {}",
                    other.command(),
                )));
            }
        };
        info!(
            "peer {} version: agent={}, height={}",
            self.address, their_version.user_agent, their_version.best_height,
        );

        // Send verack.
        self.send(&NetMessage::Verack).await?;

        // Expect their verack.
        match self.receive().await? {
            NetMessage::Verack => {}
            other => {
                warn!(
                    "expected verack from {}, got {}",
                    self.address,
                    other.command(),
                );
            }
        }

        info!("handshake complete with {}", self.address);
        Ok(their_version)
    }

    /// Perform the inbound handshake: we wait for their version, send
    /// our version + verack, then wait for their verack.
    pub async fn handshake_inbound(&mut self, our_height: u64) -> Result<VersionMessage> {
        // Expect their version first.
        let their_version = match self.receive().await? {
            NetMessage::Version(v) => v,
            other => {
                return Err(Error::Protocol(format!(
                    "expected version, got {}",
                    other.command(),
                )));
            }
        };
        info!(
            "peer {} version: agent={}, height={}",
            self.address, their_version.user_agent, their_version.best_height,
        );

        // Send our version.
        let our_version = build_version(our_height);
        self.send(&NetMessage::Version(our_version)).await?;

        // Send verack.
        self.send(&NetMessage::Verack).await?;

        // Expect their verack.
        match self.receive().await? {
            NetMessage::Verack => {}
            other => {
                warn!(
                    "expected verack from {}, got {}",
                    self.address,
                    other.command(),
                );
            }
        }

        info!("handshake complete with {}", self.address);
        Ok(their_version)
    }

    /// Consume this peer and return the raw halves plus the address.
    /// Used when the connection must be kept alive beyond the
    /// handshake (e.g., for tx gossip). The caller takes ownership of
    /// both halves and manages the lifecycle.
    pub fn into_parts(self) -> (OwnedReadHalf, OwnedWriteHalf, std::net::SocketAddr) {
        (self.reader, self.writer, self.address)
    }
}

fn build_version(best_height: u64) -> VersionMessage {
    VersionMessage {
        protocol_version: 1,
        services: 1, // full node
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        user_agent: "BitAiir Core/0.1.0".to_string(),
        best_height,
    }
}
