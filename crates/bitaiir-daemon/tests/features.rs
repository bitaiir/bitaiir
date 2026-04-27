//! End-to-end integration tests for the consensus-level commerce
//! primitives that ship with BitAiir: aliases (`@name → address`)
//! and N-of-M escrow with timeout refund.
//!
//! Each test spawns a real `bitaiird --testnet`, mines a few mature
//! coinbases for funding, then drives the alias / escrow RPCs and
//! verifies the on-chain effect.  Tests are marked `#[ignore]` for
//! the same reason as `multinode.rs`: Argon2id mining means a single
//! scenario can take 30–60 s, which is too slow for a default
//! `cargo test` run.
//!
//! Run with:
//!     cargo test --release --test features -- --ignored --nocapture

mod common;

use std::time::Duration;

use bitaiir_chain::consensus;
use bitaiir_types::Network;
use common::TestNode;
use jsonrpsee::rpc_params;
use serde_json::Value;

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

fn set_testnet() {
    Network::Testnet.set_active();
}

/// Mine until a single coinbase reward (100 AIIR) has matured into
/// the wallet, plus a small headroom so subsequent fire-and-forget
/// transactions have something to spend.  Testnet maturity is 10
/// blocks, so we mine `maturity + slack`.
async fn mine_until_funded(node: &TestNode, slack: u64) {
    let maturity = consensus::coinbase_maturity();
    let target = node.height().await + maturity + slack;
    node.set_mining(true).await;
    node.wait_for_height(target, Duration::from_secs(300))
        .await
        .expect("mine to maturity");
    node.set_mining(false).await;
}

/// Get the wallet's first/miner address.  `listaddresses` returns
/// them in insertion order; the first one is the miner address that
/// receives every coinbase reward.
async fn miner_address(node: &TestNode) -> String {
    let v: Value = node
        .rpc("listaddresses", rpc_params![])
        .await
        .expect("listaddresses");
    v.get("addresses")
        .and_then(|a| a.as_array())
        .and_then(|a| a.first())
        .and_then(|e| e.get("address"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .expect("miner address")
}

/// Issue a `getnewaddress` and return the result.  Each call yields
/// a fresh BIP44 child.
async fn new_address(node: &TestNode) -> String {
    node.rpc::<String>("getnewaddress", rpc_params![])
        .await
        .expect("getnewaddress")
}

/// Mine until `resolvealias(name)` returns a non-null result, or
/// timeout.  The alias RPC is fire-and-forget — registration mines
/// tx-PoW in the background, broadcasts, and only after the tx is
/// included in a block does the alias index see it.
async fn wait_for_alias(node: &TestNode, name: &str, timeout: Duration) -> Result<Value, String> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        // Keep mining so the alias-registration tx eventually lands.
        node.set_mining(true).await;
        let v: Value = node
            .rpc("resolvealias", rpc_params![name.to_string()])
            .await
            .unwrap_or(Value::Null);
        if v.get("address")
            .and_then(|a| a.as_str())
            .filter(|s| !s.is_empty())
            .is_some()
        {
            node.set_mining(false).await;
            return Ok(v);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    node.set_mining(false).await;
    Err(format!("alias {name} never resolved within {timeout:?}"))
}

/// Same idea for escrow: poll `listescrows` until at least one entry
/// is reported, then return the array.
async fn wait_for_escrow(node: &TestNode, timeout: Duration) -> Result<Value, String> {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        node.set_mining(true).await;
        let v: Value = node
            .rpc("listescrows", rpc_params![])
            .await
            .unwrap_or(Value::Null);
        let count = v.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
        if count > 0 {
            node.set_mining(false).await;
            return Ok(v);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    node.set_mining(false).await;
    Err(format!("no escrow ever appeared within {timeout:?}"))
}

// ===========================================================================
// 1. Aliases
// ===========================================================================

#[tokio::test]
#[ignore = "spawns real bitaiird, runs in release mode only"]
async fn alias_register_resolve_and_list() {
    set_testnet();
    let node = TestNode::spawn().await;

    // Fund the wallet.
    mine_until_funded(&node, 2).await;

    // Pick a fresh address to point the alias at — different from
    // the miner address — so we can confirm `resolvealias` actually
    // returns the value we registered, not just any wallet address.
    let target = new_address(&node).await;
    // The on-chain alias name is the bare lowercase string; the
    // `@alice` form is just the user-facing display convention
    // (`resolvealias` strips a leading `@`, `registeralias` requires
    // the bare name).  See `validate_alias_name` in `bitaiir-types`.
    let name = "alice";

    // Fire-and-forget registration.  The RPC returns immediately
    // (tx-PoW + broadcast happen in a background task).
    let _: Value = node
        .rpc(
            "registeralias",
            rpc_params![name.to_string(), target.clone(), Option::<String>::None],
        )
        .await
        .expect("registeralias");

    // Mine until the registration tx is included in a block and the
    // alias index sees it.  Resolve via `@alice` to also exercise
    // the prefix-stripping path of `resolvealias`.
    let resolved = wait_for_alias(&node, "@alice", Duration::from_secs(300))
        .await
        .expect("alias resolves");

    let address = resolved
        .get("address")
        .and_then(|a| a.as_str())
        .expect("address field");
    assert_eq!(address, target, "alias resolves to the registered address");

    // listaliases must include the new entry.  The alias name is
    // stored normalized (lowercase, no `@` prefix), and the entry
    // shape exposes it under the `alias` key — see
    // `list_aliases` in `bitaiir-rpc`.
    let listed: Value = node
        .rpc("listaliases", rpc_params![])
        .await
        .expect("listaliases");
    let aliases = listed
        .get("aliases")
        .and_then(|a| a.as_array())
        .expect("aliases array");
    let found = aliases.iter().any(|entry| {
        entry.get("alias").and_then(|n| n.as_str()) == Some(name)
            && entry.get("address").and_then(|a| a.as_str()) == Some(target.as_str())
    });
    assert!(
        found,
        "registered alias not present in listaliases response: {listed}"
    );
}

#[tokio::test]
#[ignore = "spawns real bitaiird, runs in release mode only"]
async fn resolve_alias_errors_on_unregistered_name() {
    set_testnet();
    let node = TestNode::spawn().await;

    // No mining / registration — fresh chain has no aliases.
    // `resolve_alias` returns a JSON-RPC error (not a null result)
    // when the name isn't in the alias index.
    let result = node
        .rpc::<Value>("resolvealias", rpc_params!["@nobody".to_string()])
        .await;
    let err = result.expect_err("expected resolvealias to fail for unregistered name");
    assert!(
        err.contains("not found"),
        "error should mention the alias was not found, got: {err}"
    );
}

// ===========================================================================
// 2. Escrow
// ===========================================================================

#[tokio::test]
#[ignore = "spawns real bitaiird, runs in release mode only"]
async fn escrow_creation_lands_in_listescrows() {
    set_testnet();
    let node = TestNode::spawn().await;

    // Need a couple of mature coinbases so escrow has a UTXO to lock.
    mine_until_funded(&node, 5).await;

    // Build a 2-of-3 escrow.  Three new addresses act as the
    // signers; `refund_address` is the miner so refunds (post-
    // timeout) come back to where the funds originated.
    let signer_a = new_address(&node).await;
    let signer_b = new_address(&node).await;
    let signer_c = new_address(&node).await;
    let refund = miner_address(&node).await;

    // Use a generous timeout (1 000 blocks ≈ 1.4 h at testnet 5 s
    // block time) so the refund path doesn't accidentally trigger
    // during the test run.
    let amount: f64 = 5.0;
    let m: u8 = 2;
    let timeout_blocks: u32 = 1_000;

    let _: Value = node
        .rpc(
            "createescrow",
            rpc_params![
                amount,
                m,
                vec![signer_a.clone(), signer_b.clone(), signer_c.clone()],
                timeout_blocks,
                refund.clone()
            ],
        )
        .await
        .expect("createescrow");

    // Wait for the escrow tx to confirm and the escrow index to
    // catch up.
    let listed = wait_for_escrow(&node, Duration::from_secs(300))
        .await
        .expect("escrow appears");

    let escrows = listed
        .get("escrows")
        .and_then(|e| e.as_array())
        .expect("escrows array");
    assert!(!escrows.is_empty(), "expected at least one escrow");

    // Sanity-check the first entry against what `list_escrows`
    // emits in `bitaiir-rpc`: m, n, signers (addresses), timeout
    // height, refund address, plus the locked amount + outpoint.
    let entry = &escrows[0];
    let reported_m = entry.get("m").and_then(|v| v.as_u64()).unwrap_or(0);
    assert_eq!(reported_m, m as u64, "m mismatch in {entry}");

    let reported_n = entry.get("n").and_then(|v| v.as_u64()).unwrap_or(0);
    assert_eq!(reported_n, 3, "n should be 3 (we passed 3 signers)");

    let signers = entry
        .get("signers")
        .and_then(|v| v.as_array())
        .expect("signers array on escrow entry");
    assert_eq!(signers.len(), 3);
    let signers_set: std::collections::HashSet<&str> =
        signers.iter().filter_map(|v| v.as_str()).collect();
    for expected in [&signer_a, &signer_b, &signer_c] {
        assert!(
            signers_set.contains(expected.as_str()),
            "expected signer {expected} in {signers:?}"
        );
    }

    let reported_refund = entry
        .get("refund_address")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(reported_refund, refund);
}
