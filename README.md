<h1 align="center">
<img src="https://i.imgur.com/ffJhKBu.png" alt="BitAiir Logo" width="200"/>
<br/>
BitAiir Core
</h1>

<div align="center">
<h3>
A decentralized payment cryptocurrency — fast, zero-fee, and mineable by anyone.
</h3>

![Stars](https://img.shields.io/github/stars/bitaiir/bitaiir?style=social)
![MIT License](https://img.shields.io/github/license/bitaiir/bitaiir)
![contributors](https://img.shields.io/github/contributors-anon/bitaiir/bitaiir)
![Forks](https://img.shields.io/github/forks/bitaiir/bitaiir?style=social)
![size](https://img.shields.io/github/languages/code-size/bitaiir/bitaiir)
</div>

---

## What is BitAiir?

BitAiir is a cryptocurrency designed for **everyday payments** — inspired by Brazil's Pix instant-payment system and built on Bitcoin's proven UTXO architecture. It combines fast 5-second block times, zero transaction fees, and a novel proof-of-work algorithm called **Proof of Aiir** that keeps mining accessible to anyone with a regular computer.

### Key Features

- **Proof of Aiir** — SHA-256d wrapped in Argon2id (64 MiB memory-hard). Resists ASICs and GPUs so commodity CPUs stay competitive.
- **5-second block time** — payments confirm in seconds, not minutes.
- **Zero fees** — transactions are free. Anti-spam is enforced via a per-transaction proof of work (~2 seconds of sender CPU time) instead of fees.
- **Tail emission** — block rewards halve like Bitcoin but never reach zero. A permanent floor of 10 AIIR/block ensures miners are always paid.
- **Interactive TUI** — a terminal interface with slash-commands, autocomplete, scrollable logs, and real-time mining output.
- **P2P networking** — nodes connect, sync chains, and propagate transactions and blocks automatically.
- **Persistent storage** — chain data survives restarts via an embedded database (redb).

---

## Quick Start

### Build

Requires [Rust](https://rustup.rs/) (stable, edition 2024).

```bash
git clone https://github.com/bitaiir/bitaiir.git
cd bitaiir
cargo build --release --bin bitaiird --bin bitaiir-cli
```

### Run (Interactive Mode)

```bash
./target/release/bitaiird -i
```

This opens the TUI where you can type commands directly:

```
╭ BitAiir Core v0.1.0 ──────────────────────────────────────────╮
│                                                                │
│  Type / to see commands. Example: /mine-start                  │
│                                                                │
│  > /mine-start                                                 │
│  "Mining started."                                             │
│                                                                │
│  Mining started.                                               │
│  Height | Hash            | Reward      | Nonce | Time | UTXOs │
│  ----------------------------------------------------------------│
│       1 | 8c25dd...e409   | 100 AIIR    |  327  | 2.1s |    2 │
│       2 | 95ced1...4e70   | 100 AIIR    |   84  | 0.8s |    3 │
│                                                                │
│  > /getnewaddress                                              │
│  "aiir1KXgUaSrv31thw41QTrb3MpK9FBziQQZ8T"                     │
│                                                                │
│  > /sendtoaddress aiir1KXg... 10                               │
│  { "txid": "5cbe93...", "status": "added to mempool" }         │
│                                                                │
╰────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────────────╮
│ bitaiir> /_                                                    │
╰────────────────────────────────────────────────────────────────���
```

### Run (Daemon Mode)

```bash
# Start the daemon (no mining by default, like bitcoind)
./target/release/bitaiird

# Start with mining enabled
./target/release/bitaiird --mine

# In another terminal, use the CLI
./target/release/bitaiir-cli getblockchaininfo
./target/release/bitaiir-cli mine-start
./target/release/bitaiir-cli getnewaddress
./target/release/bitaiir-cli sendtoaddress aiir1... 10.0
./target/release/bitaiir-cli stop
```

---

## Commands

All commands work in both the TUI (with `/` prefix) and the CLI.

| Command | Description |
|---|---|
| `getblockchaininfo` | Chain height, tip hash, UTXO count, next subsidy |
| `getblock <height>` | Block details (hash, nonce, timestamp, transactions) |
| `getnewaddress` | Generate a new BitAiir address |
| `getbalance <address>` | Show the balance of an address |
| `listaddresses` | List all wallet addresses with balances |
| `sendtoaddress <addr> <amt>` | Send AIIR to an address |
| `getmempoolinfo` | Number of pending transactions |
| `mine-start` | Start mining |
| `mine-stop` | Stop mining |
| `addpeer <ip:port>` | Connect to another BitAiir node |
| `stop` | Shut down the daemon |

---

## P2P Networking

Two nodes on the same machine:

```bash
# Terminal 1: Node A
./target/release/bitaiird --mine

# Terminal 2: Node B (different ports and data dir)
./target/release/bitaiird --rpc-addr 127.0.0.1:8442 --p2p-addr 127.0.0.1:8445 --data-dir bitaiir_data_b --no-mine

# Terminal 3: Connect B to A (syncs blocks automatically)
./target/release/bitaiir-cli --rpc-url http://127.0.0.1:8442 addpeer 127.0.0.1:8444
```

Node B downloads all missing blocks from Node A, validates each one, and persists to disk. Transactions broadcast automatically between connected peers.

### Seed nodes and DNS seeds

A fresh node (no saved `known_peers`, no `--connect`) bootstraps by consulting two compiled-in fallbacks, in order:

1. **DNS seeds** — hostnames whose A/AAAA records resolve to healthy peers. Re-resolved every hour.
2. **Hardcoded seed nodes** — a short list of long-lived static-IP nodes embedded in the binary.

Both lists are network-specific (mainnet/testnet) and live in `crates/bitaiir-daemon/src/peer_manager.rs` (`SEED_NODES_MAINNET`, `DNS_SEEDS_MAINNET`, and the testnet counterparts). They are currently empty — the network is in development and has no public infrastructure yet.

**Running a DNS seeder:** the reference implementation is [`bitcoin-seeder`](https://github.com/sipa/bitcoin-seeder). The pattern is the same for BitAiir:

1. Run a crawler that connects to known BitAiir nodes, follows `getaddr`/`addr` gossip to discover more, and ranks them by uptime and recency.
2. Expose an authoritative DNS server for a hostname (e.g. `seed.bitaiir.org`) that returns rotating A/AAAA records drawn from the top-ranked peers.
3. Register the hostname in the appropriate `DNS_SEEDS_*` array and ship a new release.

Static seed nodes are simpler: operate a BitAiir node on a static IP, commit its `"ip:port"` string to the appropriate `SEED_NODES_*` array, and release.

---

## Protocol Summary

| Parameter | Value |
|---|---|
| Block time | 5 seconds |
| Proof of work | Proof of Aiir (SHA-256d + Argon2id 64 MiB) |
| Initial reward | 100 AIIR |
| Halving interval | 50,000,000 blocks (~7.9 years) |
| Tail emission | 10 AIIR/block forever |
| Transaction fees | Optional (zero by default) |
| Anti-spam | Per-transaction PoW (~2s CPU) |
| Difficulty retarget | Every 20 blocks (~100 seconds) |
| Address format | `aiir` prefix + Base58Check |
| WIF version byte | `0xfe` |
| Network magic | `0xB1 0x7A 0x11 0xED` |
| P2P port | 8444 |
| RPC port | 8443 |

Full protocol specification: [`docs/protocol.md`](docs/protocol.md)

---

## Architecture

```
crates/
├── bitaiir-crypto     Hashing, ECDSA, Base58, WIF, addresses, signed messages
├── bitaiir-types      Block, Transaction, Hash256, Amount, merkle root, encoding
├── bitaiir-chain      Consensus rules, validation, UTXO set, mempool, mining, PoW
├── bitaiir-storage    Persistent storage (redb)
├── bitaiir-net        P2P wire protocol, handshake, block sync, tx gossip
├── bitaiir-rpc        JSON-RPC server (jsonrpsee)
├── bitaiir-node       Integration library (future)
├── bitaiir-daemon     bitaiird binary (daemon + TUI)
└── bitaiir-cli        bitaiir-cli binary (command-line client)
```

Cross-language test vectors in `tests/vectors/crypto.json` validate the Rust implementation against the Python reference implementation in `reference/python/`.

---

## Genesis Block

```
Message: "Poder360 29/03/2026 Master deixa rombo de R$ 52 bi no FGC e de R$ 2 bi em fundos"
```

---

## Building from Source

```bash
# Install Rust (if you don't have it)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and build
git clone https://github.com/bitaiir/bitaiir.git
cd bitaiir
cargo build --release

# Run tests (102 tests)
cargo test --workspace

# Install globally
cargo install --path crates/bitaiir-daemon
cargo install --path crates/bitaiir-cli
```

### Windows

```powershell
# Install Rust from https://rustup.rs/ (includes MSVC build tools)
git clone https://github.com/bitaiir/bitaiir.git
cd bitaiir
cargo build --release
.\target\release\bitaiird.exe -i
```

---

## Data Directory

BitAiir stores its blockchain database in `./bitaiir_data/` (relative to the working directory). To start fresh, delete this directory:

```bash
rm -rf bitaiir_data
```

---

## License

[MIT](LICENSE)

---

<div align="center">

**BitAiir** is built by [The BitAiir Developers](https://github.com/bitaiir).

</div>
