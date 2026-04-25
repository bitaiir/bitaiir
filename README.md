<h1 align="center">
<img src="https://i.imgur.com/ffJhKBu.png" alt="BitAiir Logo" width="200"/>
<br/>
BitAiir Core
</h1>

<div align="center">
<h3>
Decentralized P2P payments with native escrow for commerce — fast, zero-fee, and mineable by anyone.
</h3>

![Stars](https://img.shields.io/github/stars/bitaiir/bitaiir?style=social)
![MIT License](https://img.shields.io/github/license/bitaiir/bitaiir)
![contributors](https://img.shields.io/github/contributors-anon/bitaiir/bitaiir)
![Forks](https://img.shields.io/github/forks/bitaiir/bitaiir?style=social)
![size](https://img.shields.io/github/languages/code-size/bitaiir/bitaiir)

</div>

> ⚠️ **Pre-mainnet.** Mainnet is not live yet — the public testnet is the only way to run a real node today. Use `--testnet` everywhere.

---

## What is BitAiir?

BitAiir is a cryptocurrency built from scratch in Rust for **everyday payments and direct buy/sell**. The design borrows Bitcoin's UTXO architecture and Pix's "instant, no intermediaries" UX, then layers two consensus-level primitives on top: **on-chain aliases** (`@name → address`) and **N-of-M escrow with timeout refund**. The result is a small protocol surface that handles tipping, paying a merchant, milestone work, and group buys without smart contracts and without trusting a custodian.

Mining is **Proof of Aiir**: SHA-256d wrapped in 64 MiB of Argon2id, so an ASIC has no advantage over your laptop. Transactions carry a tiny per-tx proof of work (~1 s of CPU) instead of fees, which keeps the chain spam-resistant without ever charging users.

---

## Highlights

### Network
- **Proof of Aiir** — SHA-256d + Argon2id (64 MiB, memory-hard). Anti-ASIC, anti-GPU.
- **5-second blocks** — 20-block retarget converges quickly.
- **Zero fees, ever** — anti-spam is per-tx PoW (~1 s on a commodity laptop). Senders can declare a higher `pow_priority` to mine faster than the next user.
- **Tail emission** — block reward halves every 50 M blocks but never falls below 10 AIIR; miners are paid forever.
- **Compact-block relay (BIP 152-style)** + Bitcoin-style block locator for one-shot ancestor sync.
- **Atomic reorg** — full UTXO undo, both in memory (snapshot/restore) and on disk (single redb transaction).

### Wallet
- **HD wallet** — BIP32 / BIP39 (24-word mnemonic) / BIP44, single-seed multi-address.
- **AES-256-GCM + Argon2id** wallet encryption with `walletpassphrase` / `walletlock`.
- **WIF import/export**, full backup/restore to JSON.
- **`@alias` resolution** in `sendtoaddress` — pay a human-friendly name instead of a 34-char string.

### Commerce primitives (consensus-level)
- **Aliases** — on-chain name registry. Lock 1 AIIR to claim `@yourname`, ~1-year validity, owner-renew, anyone-can-spend after expiry.
- **Escrow N-of-M** — single output type covers 2-of-3 arbitrated purchase, milestone payouts, and group buys. M-of-N signatures before timeout, single-sig refund after. Up to 15 signers.

### Operator experience
- **Interactive TUI** with slash-commands, autocomplete, mouse selection, and a live mining log.
- **JSON-RPC over HTTPS** — auto-generated self-signed cert by default; bring your own cert if you prefer.
- **Cookie auth + IP allow-list** — zero-config local use, optional `[rpc]` user/password and `allow_ip` for LAN.
- **Headless build** — drop the TUI for smaller server / container / RISC-V binaries.

---

## Quick Start

### Docker

Pre-built images are published to GitHub Container Registry on every release.

```bash
# Testnet node, persistent data in a named volume.
docker run -d --name bitaiir \
    -v bitaiir_testnet:/data \
    -p 18443:18443 -p 18444:18444 \
    ghcr.io/bitaiir/bitaiir:latest \
    --testnet \
    --rpc-addr 0.0.0.0:18443 \
    --p2p-addr 0.0.0.0:18444

# Query through the bundled CLI inside the container.
docker exec bitaiir bitaiir-cli --testnet getblockchaininfo
```

`:latest` tracks the newest stable release; pin to `:v0.1.0` (or any tag) for reproducibility.

### Build from source

Requires [Rust](https://rustup.rs/) (stable, edition 2024).

```bash
git clone https://github.com/bitaiir/bitaiir.git
cd bitaiir
cargo build --release --bin bitaiird --bin bitaiir-cli
```

**Headless build** (no TUI, no clipboard, no X11 runtime dep — smaller binary for server / container / RISC-V):

```bash
cargo build --release -p bitaiir-daemon --no-default-features
```

The `-i` / `--interactive` flag is rejected at startup in this build — talk to the node via `bitaiir-cli`.

### Run on testnet (interactive)

```bash
./target/release/bitaiird --testnet -i --mine
```

Opens the TUI with mining enabled. Type `/` to see commands.

```
╭ BitAiir Core v0.1.0 ──────────────────────────────────────────╮
│  Network:    testnet                                           │
│  Proof of Aiir (SHA-256d + Argon2id)                           │
│  Target block time: 5s | Retarget every 20 blocks              │
│                                                                │
│  Mining started (4 threads).                                   │
│  Height | Hash            |     Reward |  Nonce |  Time | UTXOs│
│  --------------------------------------------------------------│
│       1 | e24f08...3b72   | 100 AIIR   |     69 |  3.2s |    2 │
│       2 | f5c283...fe86   | 100 AIIR   |    254 | 11.1s |    3 │
│                                                                │
│  > /sendtoaddress @alice 5                                     │
│  Sending transaction (anti-spam PoW ~1s)...                    │
│  { "txid": "5cbe93...", "status": "broadcast and added" }      │
╰────────────────────────────────────────────────────────────────╯
```

### Run as a daemon

```bash
# Daemon (no mining by default, like bitcoind)
./target/release/bitaiird --testnet

# Mining enabled
./target/release/bitaiird --testnet --mine

# In another terminal, talk to it via the CLI
./target/release/bitaiir-cli --testnet getblockchaininfo
./target/release/bitaiir-cli --testnet getnewaddress
./target/release/bitaiir-cli --testnet sendtoaddress aiir1... 10.0
./target/release/bitaiir-cli --testnet stop
```

---

## Commands

All commands work in both the TUI (with `/` prefix) and `bitaiir-cli`.

### Chain & blocks
| Command | Description |
|---|---|
| `getblockchaininfo` | Chain height, tip hash, UTXO count, mempool size |
| `getblock <height>` | Block details (header, transactions) |
| `getmempoolinfo` | Pending transactions (count, size, priority histogram) |
| `gettransaction <txid>` | Look up a transaction by id |
| `gettransactionhistory <addr>` | All txs touching an address |

### Wallet
| Command | Description |
|---|---|
| `getnewaddress` | Generate a new HD-derived address |
| `getbalance <address>` | Spendable / immature / pending balance |
| `listaddresses` | All wallet addresses with balances |
| `sendtoaddress <addr\|@alias> <amt> [pri] [from]` | Send AIIR; optional priority and source address |
| `getmnemonic` | Show the 24-word HD seed phrase |
| `importmnemonic <words>` | Restore a wallet from a seed phrase |
| `encryptwallet <passphrase>` | Encrypt the wallet at rest |
| `walletpassphrase <pw> <secs>` | Unlock the wallet for N seconds |
| `walletlock` | Lock the wallet immediately |
| `exportwallet <file>` | Export keys to a JSON backup |
| `importwallet <file>` | Restore from a JSON backup |
| `importprivkey <wif>` | Add a single key to the wallet |

### Aliases
| Command | Description |
|---|---|
| `registeralias <@name> [from]` | Lock 1 AIIR to claim a name (~1-year validity) |
| `resolvealias <@name>` | Look up the address backing a name |
| `listaliases [filter]` | All aliases owned by the wallet |

### Escrow
| Command | Description |
|---|---|
| `createescrow <m> <signers> <amt> <timeout> <refund>` | Lock AIIR in an M-of-N escrow |
| `refundescrow <txid>` | Refund an expired escrow back to the sender |
| `listescrows` | Active escrows owned by the wallet |

### Mining & networking
| Command | Description |
|---|---|
| `mine-start` / `mine-stop` | Start or stop the mining loop |
| `addpeer <ip:port>` | Connect to another BitAiir node |
| `listpeers` | Currently connected peers |
| `listknownpeers` | All peers ever discovered (for reconnect) |
| `stop` | Shut down the daemon cleanly |

---

## P2P networking

Two nodes on the same machine:

```bash
# Terminal 1: Node A (mining)
./target/release/bitaiird --testnet --mine

# Terminal 2: Node B (different ports + data dir)
./target/release/bitaiird --testnet \
    --rpc-addr 127.0.0.1:18445 \
    --p2p-addr 127.0.0.1:18446 \
    --data-dir bitaiir_testnet_data_b \
    --no-mine

# Terminal 3: Connect B → A
./target/release/bitaiir-cli --testnet \
    --rpc-url https://127.0.0.1:18445 \
    addpeer 127.0.0.1:18444
```

Node B downloads missing blocks via header-first sync + compact-block relay, validates each one, and persists to disk. Transactions broadcast automatically between connected peers.

### Seed nodes and DNS seeds

A fresh node (no saved `known_peers`, no `--connect`) bootstraps from two compiled-in fallbacks, in order:

1. **DNS seeds** — hostnames whose A/AAAA records resolve to healthy peers. Re-resolved every hour.
2. **Hardcoded seed nodes** — a short list of long-lived static-IP nodes embedded in the binary.

Both lists are network-specific (mainnet/testnet) and live in `crates/bitaiir-daemon/src/peer_manager.rs`. They are currently empty — public infrastructure is registered ahead of v0.1.0.

Operators can extend either list at runtime without recompiling:

```bash
bitaiird --seed 198.51.100.10:8444 --dns-seed seed.example.org
bitaiird --no-dns-seeds                # skip DNS resolution entirely
```

Or via config:

```toml
[network]
seed_nodes        = ["198.51.100.10:8444"]
dns_seeds         = ["seed.example.org"]
disable_dns_seeds = false
```

CLI > config > hardcoded; lists are additive. Full operator playbook (running a seed node, registering a DNS seeder, production checklist) in [`docs/seed-operator-guide.md`](docs/seed-operator-guide.md).

---

## Protocol summary

| Parameter | Value |
|---|---|
| Block time | 5 seconds |
| Difficulty retarget | Every 20 blocks |
| Initial difficulty `bits` | `0x2001fffe` (calibrated for ~5 s on a commodity laptop) |
| Proof of work | Proof of Aiir (SHA-256d + Argon2id 64 MiB) |
| Initial reward | 100 AIIR |
| Halving interval | 50 000 000 blocks (~7.9 years) |
| Tail emission | 10 AIIR/block forever |
| Transaction fees | None (zero by protocol) |
| Anti-spam | Per-tx PoW, 20 leading zero bits (~1 s CPU at priority 1) |
| Address format | `aiir` prefix + Base58Check |
| WIF version byte | `0xfe` |
| Network magic | `0xB1 0x7A 0x11 0xED` (mainnet) / distinct on testnet |
| Default ports | 8443 RPC / 8444 P2P (mainnet) — 18443 / 18444 (testnet) |
| Coinbase maturity | 100 blocks (mainnet) / 10 blocks (testnet) |

Full specification: [`docs/protocol.md`](docs/protocol.md).

---

## Architecture

```
crates/
├── bitaiir-crypto     Hashing, secp256k1 ECDSA, Base58/WIF, addresses, AES+Argon2 wallet, BIP32/39/44
├── bitaiir-types      Block, Transaction (incl. pow_priority), TxOut variants (P2PKH/escrow/alias), encoding
├── bitaiir-chain      Consensus rules, validation, UTXO + undo, mempool, mining, tx-PoW, fork choice
├── bitaiir-storage    Persistent storage (redb): blocks, UTXOs, undo, peers, atomic apply_reorg
├── bitaiir-net        P2P wire protocol, framing, compact blocks, block locator
├── bitaiir-rpc        JSON-RPC server (jsonrpsee) + wallet, alias / escrow / mining RPCs
├── bitaiir-daemon     bitaiird binary: orchestration, TUI, config, RPC auth, peer manager
└── bitaiir-cli        bitaiir-cli binary: thin JSON-RPC client (cookie + --rpc-user)
```

Cross-language test vectors in `tests/vectors/crypto.json` validate the Rust implementation against the Python reference in `reference/python/`.

---

## Building and testing

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and build
git clone https://github.com/bitaiir/bitaiir.git
cd bitaiir
cargo build --release

# Lints and tests (143 unit + integration tests)
cargo fmt --all
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked

# Install globally
cargo install --path crates/bitaiir-daemon
cargo install --path crates/bitaiir-cli
```

### Benchmarks

```bash
# Block PoW (Argon2id 64 MiB) hash rate, single-thread
cargo run --release -p bitaiir-chain --example bench_block_pow

# tx-PoW timing at priorities 1, 2, 5
cargo run --release -p bitaiir-chain --example bench_tx_pow
```

### Windows

```powershell
# Install Rust from https://rustup.rs/ (includes MSVC build tools)
git clone https://github.com/bitaiir/bitaiir.git
cd bitaiir
cargo build --release
.\target\release\bitaiird.exe --testnet -i --mine
```

---

## Data directory

BitAiir stores chain data, wallet, and the auth cookie in a per-network directory:

- Mainnet: `./bitaiir_data/`
- Testnet: `./bitaiir_testnet_data/`

To start fresh (e.g. after a consensus-level change in pre-mainnet):

```bash
rm -rf bitaiir_testnet_data
```

Override with `--data-dir <path>`.

---

## Genesis block

```
Mainnet message: "Poder360 29/03/2026 Master deixa rombo de R$ 52 bi no FGC e de R$ 2 bi em fundos"
Testnet message: "BitAiir Testnet Genesis"
```

Each network mines its own genesis at first start with parameters fixed by the protocol, so every node arrives at the same block independently.

---

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a PR. Highlights:

- All changes land via PR + squash merge — `master` is protected.
- Conventional Commits (`type(scope): summary`) and DCO sign-off (`git commit -s`).
- Lints/tests must be green on Linux, macOS, Windows, and a RISC-V cross-build.

Security disclosures: see [`SECURITY.md`](SECURITY.md).

---

## License

[MIT](LICENSE)

---

<div align="center">

**BitAiir** is built by [The BitAiir Developers](https://github.com/bitaiir).

</div>
