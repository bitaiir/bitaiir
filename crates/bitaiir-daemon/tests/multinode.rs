//! Multi-node integration tests.
//!
//! Every test spawns 2–3 real `bitaiird` processes on unique
//! testnet ports, connects them, and exercises the full stack
//! (storage → chain → net → RPC) end-to-end.  The tests are slow
//! compared to unit tests — each daemon mines at least a few blocks
//! via Argon2id — so the timeouts are deliberately generous.
//!
//! Run a single scenario with:
//!     cargo test --test multinode sync_empty_node_catches_up -- --nocapture
//!
//! Some scenarios (rate-limit flood, TLS) require the `rustls` ring
//! provider to be installed globally.  The test helper takes care of
//! that lazily on first use.

mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use bitaiir_net::message::NetMessage;
use bitaiir_net::peer::Peer;
use bitaiir_types::Network;
use common::{NodeConfig, TestNode};
use jsonrpsee::rpc_params;
use serde_json::Value;
use tokio::net::TcpStream;

/// `bitaiir-net` frames messages with magic bytes that depend on the
/// globally-active network, so the flood test must match what the
/// daemons are running (testnet).
fn set_testnet() {
    Network::Testnet.set_active();
}

/// Mine `n` blocks on `node`, then stop mining.  Timeout is
/// generous — on a warm CPU Argon2id at 64 MiB runs ~1–3 s/block
/// in release, but parallel tests and CI runners slow it down.
async fn mine_blocks(node: &TestNode, n: u64) {
    let start = node.height().await;
    node.set_mining(true).await;
    node.wait_for_height(start + n, Duration::from_secs(300))
        .await
        .expect("mine blocks");
    node.set_mining(false).await;
}

/// Helper: `127.0.0.1:<p2p>` — used to build `--connect` args.
fn p2p_addr(node: &TestNode) -> String {
    format!("127.0.0.1:{}", node.p2p_port)
}

/// Wait until `leader` and `follower` converge on the same tip
/// hash at the same height.  Needed because the mining loop is
/// async: even after `set_mining(false)`, the miner may finalize
/// one more block before observing the stop signal, so a tip
/// captured earlier can silently be overtaken.  Polls leader's
/// current height every 500 ms and requires both the height and
/// the hash to agree.
async fn wait_for_convergence(leader: &TestNode, follower: &TestNode, timeout: Duration) {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        let l_height = leader.height().await;
        if follower
            .wait_for_height(l_height, Duration::from_secs(2))
            .await
            .is_ok()
            && leader.tip_hash().await == follower.tip_hash().await
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        leader.tip_hash().await,
        follower.tip_hash().await,
        "leader and follower never converged on the same tip within {:?}",
        timeout,
    );
}

// ===========================================================================
// 1. Initial sync
// ===========================================================================

#[tokio::test]
#[ignore = "multi-node — spawns real bitaiird processes, runs in release mode only"]
async fn sync_empty_node_catches_up() {
    let a = TestNode::spawn().await;
    mine_blocks(&a, 5).await;

    // B starts fresh (only genesis), learns about A, sucks down the 5
    // new blocks via header-first sync + block relay.
    let b = TestNode::spawn().await;
    assert_eq!(b.height().await, 0);

    b.connect_to(&a).await;
    b.wait_for_height(5, Duration::from_secs(30))
        .await
        .expect("B should sync to height 5");

    wait_for_convergence(&a, &b, Duration::from_secs(30)).await;
}

// ===========================================================================
// 2. Transaction propagation
// ===========================================================================

#[tokio::test]
#[ignore = "multi-node — spawns real bitaiird processes, runs in release mode only"]
async fn tx_created_on_a_lands_in_b_mempool() {
    let a = TestNode::spawn().await;

    // Mine enough blocks for the coinbase to mature (testnet = 10).
    mine_blocks(&a, 12).await;

    let b = TestNode::spawn().await;
    b.connect_to(&a).await;
    b.wait_for_height(12, Duration::from_secs(30))
        .await
        .expect("B syncs");

    // Create a recipient on B and have A send to it.  The tx lands
    // in A's mempool first, then propagates to B.
    let new_addr: Value = b
        .rpc("getnewaddress", rpc_params![])
        .await
        .expect("getnewaddress");
    let addr = new_addr
        .get("address")
        .and_then(|s| s.as_str())
        .or_else(|| new_addr.as_str())
        .expect("address string")
        .to_string();

    let _: Value = a
        .rpc("sendtoaddress", rpc_params![addr, 10.0])
        .await
        .expect("sendtoaddress");

    // `sendtoaddress` is fire-and-forget: it reserves inputs and
    // kicks tx-PoW mining (~2s) in a background task, then broadcasts.
    // Give B up to 60s to see the tx land in its mempool.
    b.wait_for_mempool(1, Duration::from_secs(60))
        .await
        .expect("tx never reached B's mempool");
}

// ===========================================================================
// 3. Block propagation (compact blocks)
// ===========================================================================

#[tokio::test]
#[ignore = "multi-node — spawns real bitaiird processes, runs in release mode only"]
async fn blocks_mined_on_a_propagate_to_b() {
    let a = TestNode::spawn().await;

    // `addpeer` spawns a minimal RPC-side gossip loop that only
    // processes `TxData` + `Ping` — compact blocks get ignored.
    // Route the connection through `--connect` so B uses the
    // full `peer_manager::run_gossip_loop` that handles block
    // relay.
    let a_addr = p2p_addr(&a);
    let b = TestNode::spawn_with(NodeConfig {
        connect: vec![a_addr],
        ..Default::default()
    })
    .await;

    // peer_manager ticks every 10 s; first connect attempt lands
    // shortly after that.
    b.wait_for_peers(1, Duration::from_secs(30))
        .await
        .expect("B connects to A");

    // Mine live on A — each block should arrive on B via compact
    // block relay as soon as it's found.
    a.set_mining(true).await;
    b.wait_for_height(3, Duration::from_secs(180))
        .await
        .expect("B receives live-mined blocks");
    a.set_mining(false).await;

    wait_for_convergence(&a, &b, Duration::from_secs(30)).await;
}

// ===========================================================================
// 4. Reorg — most-work chain wins
// ===========================================================================

#[tokio::test]
#[ignore = "multi-node — spawns real bitaiird processes, runs in release mode only"]
async fn reorg_converges_on_most_work_chain() {
    // A and B mine in isolation on forks of the same genesis.
    let a = TestNode::spawn().await;
    let mut b = TestNode::spawn().await;

    // A gets a head-start of at least 4 blocks over B so it has
    // unambiguously more cumulative work.  Mining is async — the
    // real height may be a block or two above `n` by the time
    // `set_mining(false)` settles.
    mine_blocks(&a, 7).await;
    mine_blocks(&b, 3).await;

    let a_height_before = a.height().await;
    let b_height_before = b.height().await;
    assert_ne!(a.tip_hash().await, b.tip_hash().await, "forks should differ");
    assert!(
        a_height_before > b_height_before,
        "A must have more work than B (A={a_height_before}, B={b_height_before})",
    );

    // To reorg B onto A's heavier chain we need header-first sync
    // (block locator → GetHeaders → Headers → block bodies →
    // reorg).  The `addpeer` RPC uses a minimal linear sync that
    // silently rejects out-of-order parents, so we restart B with
    // `--connect <A>` which routes the connection through
    // `peer_manager::run_gossip_loop` instead.
    let b_data = b.take_data_dir();
    drop(b);

    let a_addr = p2p_addr(&a);
    let b = TestNode::spawn_with(NodeConfig {
        reuse_dir: Some(b_data),
        connect: vec![a_addr],
        ..Default::default()
    })
    .await;

    // peer_manager ticks every 10 s; reorg includes downloading
    // every block on A's chain sequentially.  We check height
    // rather than tip hash because the exact tip captured earlier
    // may have been overtaken by a mining-leak block that
    // finalized after `set_mining(false)` was called — height
    // proves the reorg engaged regardless of the precise tip.
    b.wait_for_height(a_height_before, Duration::from_secs(180))
        .await
        .expect("B reorgs onto A's heavier chain");

    wait_for_convergence(&a, &b, Duration::from_secs(60)).await;
}

// ===========================================================================
// 5. Rate-limit ban — flooder gets dropped
// ===========================================================================

#[tokio::test]
#[ignore = "multi-node — spawns real bitaiird processes, runs in release mode only"]
async fn rate_limit_disconnects_and_bans_flooder() {
    set_testnet();
    let a = TestNode::spawn().await;

    // Open a raw P2P connection, complete the outbound handshake,
    // then spam Pings as fast as the socket will accept until the
    // daemon closes us (bucket default: 100 msgs/s, burst 200).
    let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), a.p2p_port);
    let stream = TcpStream::connect(peer_addr).await.expect("tcp connect");
    let mut peer = Peer::new(stream, peer_addr);
    peer.handshake_outbound(0).await.expect("handshake");

    let mut sent: u64 = 0;
    for i in 0..10_000u64 {
        if peer.send(&NetMessage::Ping(i)).await.is_err() {
            break;
        }
        sent = i + 1;
    }
    assert!(
        sent > 100,
        "daemon disconnected too early ({sent} pings) — rate limit may be too strict",
    );

    // The daemon should have banned 127.0.0.1; a fresh connection
    // is dropped during/after the handshake.
    let stream = TcpStream::connect(peer_addr).await.expect("reconnect tcp");
    let mut banned_peer = Peer::new(stream, peer_addr);
    let handshake_result =
        tokio::time::timeout(Duration::from_secs(5), banned_peer.handshake_outbound(0)).await;
    match handshake_result {
        Ok(Err(_)) => { /* expected: handshake failed */ }
        Err(_) => { /* expected: timeout, daemon silently dropped us */ }
        Ok(Ok(_)) => panic!("banned IP completed a handshake — ban did not stick"),
    }
}

// ===========================================================================
// 6. Reconnection — restarted peer picks up where it left off
// ===========================================================================

#[tokio::test]
#[ignore = "multi-node — spawns real bitaiird processes, runs in release mode only"]
async fn peer_resyncs_after_restart() {
    let a = TestNode::spawn().await;
    mine_blocks(&a, 3).await;

    // Bring B up already peered to A so the initial sync runs
    // through the full peer_manager gossip loop (not the minimal
    // addpeer path).  That way the restart below goes down the
    // same code path and picks up every new block even if A
    // reorged or mined more meanwhile.
    let a_addr = p2p_addr(&a);
    let mut b = TestNode::spawn_with(NodeConfig {
        connect: vec![a_addr.clone()],
        ..Default::default()
    })
    .await;
    b.wait_for_height(3, Duration::from_secs(60))
        .await
        .expect("initial sync");

    // Preserve B's data dir across the restart.  Fresh ports —
    // on Windows closed sockets linger in TIME_WAIT long enough
    // that reusing the same port is racy.
    let b_data = b.take_data_dir();
    drop(b);

    // A mines more blocks while B is down.
    mine_blocks(&a, 2).await;
    let a_height_before_b = a.height().await;
    assert!(a_height_before_b >= 5);

    // Bring B back up with the SAME data dir + `--connect A` so
    // peer_manager reconnects on its first tick.
    let b = TestNode::spawn_with(NodeConfig {
        reuse_dir: Some(b_data),
        connect: vec![a_addr],
        ..Default::default()
    })
    .await;
    assert!(
        b.height().await >= 3,
        "B should resume from disk at its pre-shutdown height",
    );

    b.wait_for_height(a_height_before_b, Duration::from_secs(120))
        .await
        .expect("B catches up post-restart");

    wait_for_convergence(&a, &b, Duration::from_secs(30)).await;
}

// ===========================================================================
// 7. TLS on one side doesn't break P2P on the other
// ===========================================================================

#[tokio::test]
#[ignore = "multi-node — spawns real bitaiird processes, runs in release mode only"]
async fn tls_rpc_does_not_affect_p2p_sync() {
    // A serves RPC over HTTPS (self-signed cert auto-generated);
    // B stays on plain HTTP.  P2P between them must still work —
    // the TLS proxy is RPC-only.
    let a = TestNode::spawn_with(NodeConfig {
        config_toml: Some("[rpc]\ntls = true\n".into()),
        ..Default::default()
    })
    .await;
    let b = TestNode::spawn().await;

    mine_blocks(&a, 3).await;
    b.connect_to(&a).await;
    b.wait_for_height(3, Duration::from_secs(30))
        .await
        .expect("B syncs from a TLS-serving peer");

    wait_for_convergence(&a, &b, Duration::from_secs(30)).await;
}
