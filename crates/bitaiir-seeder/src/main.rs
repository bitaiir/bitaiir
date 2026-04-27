//! `bitaiir-seeder` — DNS seeder for the BitAiir P2P network.
//!
//! Three concurrent tokio tasks share a redb peer database:
//!
//!   - [`crawler`] connects to known peers, runs `getaddr`, and
//!     records what came back.
//!   - [`dns`] serves authoritative DNS A queries with the top-N
//!     freshest healthy peers.
//!   - The main task wires them together, parses CLI flags, and
//!     handles graceful shutdown on Ctrl-C.
//!
//! Run with:
//!
//! ```bash
//! bitaiir-seeder --testnet \
//!     --seed 1.2.3.4:18444 --seed 5.6.7.8:18444 \
//!     --zone seed.example.org \
//!     --dns-listen 0.0.0.0:5353 \
//!     --data-dir ./seeder-data
//! ```
//!
//! Operator playbook + production deployment details live in
//! `docs/seeder-operator-guide.md`.

mod crawler;
mod db;
mod dns;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bitaiir_types::Network;
use clap::Parser;
use tracing::{error, info};

use crate::db::Db;

#[derive(Parser, Debug)]
#[command(
    name = "bitaiir-seeder",
    about = "BitAiir DNS seeder — crawls the P2P network and serves the top-ranked peers as authoritative DNS records",
    version
)]
struct Args {
    /// Run on the testnet network instead of mainnet.  Sets the
    /// `bitaiir-types::Network::active()` global, which controls the
    /// magic bytes used by `bitaiir-net` framing — testnet seeders
    /// must NOT crawl mainnet peers and vice versa.
    #[arg(long)]
    testnet: bool,

    /// Initial peer to bootstrap the crawl from (`ip:port`,
    /// repeatable).  After the first round of `getaddr` gossip the
    /// crawler self-discovers more peers and these become optional.
    #[arg(long = "seed", value_name = "HOST:PORT")]
    seed: Vec<String>,

    /// DNS zone we serve authoritatively.  Recursive resolvers that
    /// query for this name receive the seeder's current top-N peer
    /// list as A records.
    #[arg(long, value_name = "HOSTNAME")]
    zone: String,

    /// Bind address for the authoritative DNS server (UDP).
    /// Defaults to a non-privileged port for development; in
    /// production set this to `0.0.0.0:53` and run behind a
    /// system-supplied port permission (CAP_NET_BIND_SERVICE on
    /// Linux) or a port-forward.
    #[arg(long, default_value = "127.0.0.1:5353")]
    dns_listen: String,

    /// Directory the seeder writes its peer database to.  One redb
    /// file per network so mainnet and testnet seeders can share a
    /// disk without colliding.
    #[arg(long, default_value = "bitaiir_seeder_data")]
    data_dir: PathBuf,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .init();

    let network = if args.testnet {
        Network::Testnet
    } else {
        Network::Mainnet
    };
    network.set_active();
    info!(target: "seeder", network = %network.name(), "starting bitaiir-seeder");

    if let Err(e) = std::fs::create_dir_all(&args.data_dir) {
        error!(target: "seeder", error = %e, dir = %args.data_dir.display(), "cannot create data dir");
        std::process::exit(1);
    }
    let db_path = args
        .data_dir
        .join(format!("seeder.{}.redb", network.name()));
    let db = match Db::open(&db_path) {
        Ok(d) => Arc::new(d),
        Err(e) => {
            error!(target: "seeder", error = %e, path = %db_path.display(), "cannot open peer DB");
            std::process::exit(1);
        }
    };
    info!(
        target: "seeder",
        path = %db_path.display(),
        peers = db.count().unwrap_or(0),
        "peer DB opened"
    );

    // Seed the DB with operator-provided initial peers.  These get
    // marked as known so the very first crawl round has something to
    // chew on; subsequent rounds discover more via `getaddr` gossip.
    let now = unix_now();
    for s in &args.seed {
        if let Err(e) = db.ensure_known(s, now) {
            error!(target: "seeder", error = %e, addr = %s, "cannot seed initial peer");
        }
    }
    if args.seed.is_empty() && db.count().unwrap_or(0) == 0 {
        error!(
            target: "seeder",
            "no seed peers and no peers in the DB — pass at least one --seed <ip:port> to bootstrap.",
        );
        std::process::exit(1);
    }

    let shutdown = Arc::new(AtomicBool::new(false));

    // Ctrl-C → flip the shutdown flag once.  Subsequent signals are
    // ignored so a second Ctrl-C doesn't tear down state mid-write.
    {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) = tokio::signal::ctrl_c().await {
                error!(target: "seeder", error = %e, "ctrl_c install failed");
                return;
            }
            info!(target: "seeder", "shutdown requested");
            shutdown.store(true, Ordering::Relaxed);
        });
    }

    let crawler_handle = {
        let db = db.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move { crawler::run(db, shutdown).await })
    };

    let dns_handle = {
        let db = db.clone();
        let shutdown = shutdown.clone();
        let zone = args.zone.clone();
        let listen = args.dns_listen.clone();
        tokio::spawn(async move { dns::run(db, &zone, &listen, shutdown).await })
    };

    let _ = crawler_handle.await;
    if let Err(e) = dns_handle.await {
        error!(target: "seeder", error = %e, "DNS task panicked");
    }
    info!(target: "seeder", "bye");
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
