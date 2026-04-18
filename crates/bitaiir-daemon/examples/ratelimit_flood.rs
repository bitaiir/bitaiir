//! Manual rate-limit smoke test.
//!
//! Connects to a running `bitaiird`, completes a normal outbound
//! handshake, then floods `Ping` messages as fast as the socket
//! will accept them.  Stops as soon as the daemon closes the
//! connection (expected: after `rate_limit_burst` messages, default
//! 200).  Reports how many `Ping`s were sent before the ban kicked
//! in — that's the effective bucket size.
//!
//! Usage — testnet (default):
//!
//! ```text
//! cargo run --release --example ratelimit_flood -- 127.0.0.1:18444
//! ```
//!
//! Mainnet:
//!
//! ```text
//! cargo run --release --example ratelimit_flood -- 127.0.0.1:8444 mainnet
//! ```
//!
//! Address defaults to `127.0.0.1:18444`, network defaults to
//! `testnet`.  Network selection is required to frame messages
//! with the correct magic bytes.

use std::net::SocketAddr;

use bitaiir_net::message::NetMessage;
use bitaiir_net::peer::Peer;
use bitaiir_types::Network;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() {
    let addr: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:18444".into())
        .parse()
        .expect("valid socket address");

    let network = match std::env::args().nth(2).as_deref() {
        Some("mainnet") => Network::Mainnet,
        _ => Network::Testnet,
    };
    network.set_active();
    println!("network: {}", network.name());

    println!("connecting to {addr}...");
    let stream = TcpStream::connect(addr).await.expect("connect");
    let mut peer = Peer::new(stream, addr);

    println!("handshaking...");
    let their = peer
        .handshake_outbound(0)
        .await
        .expect("outbound handshake");
    println!(
        "  peer user_agent={}, height={}",
        their.user_agent, their.best_height
    );

    println!("flooding Ping messages...");
    let start = std::time::Instant::now();
    let mut sent: u64 = 0;
    loop {
        match peer.send(&NetMessage::Ping(sent)).await {
            Ok(()) => {
                sent += 1;
                if sent % 50 == 0 {
                    println!("  sent {sent} Pings ({:?})", start.elapsed());
                }
            }
            Err(e) => {
                println!(
                    "connection closed after {sent} Pings ({:?}): {e}",
                    start.elapsed()
                );
                break;
            }
        }
    }

    println!("\nresult: daemon disconnected after {sent} messages");
    println!("  → if this is close to `rate_limit_burst` (default 200), rate limit fired");
    println!("  → re-running within `rate_limit_ban_secs` should fail at handshake (IP banned)");
}
