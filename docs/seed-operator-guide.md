# Seed Operator Guide

Running a public BitAiir node and getting it listed as a seed.

A node with no saved peers and no `--connect` flag has to find someone
to talk to before it can sync. BitAiir uses two compiled-in fallbacks,
in this order:

1. **DNS seeds** — hostnames whose A/AAAA records are maintained by an
   operator running a crawler. Resolved on startup and refreshed every
   hour.
2. **Hardcoded seed nodes** — static IPs embedded in the binary. Used
   when DNS is blocked or every DNS seed is down.

Both lists live in `crates/bitaiir-daemon/src/peer_manager.rs`
(`SEED_NODES_*`, `DNS_SEEDS_*`). They are network-specific (mainnet vs
testnet) so a node never accidentally peers across networks.

This doc walks through the two routes operators take to contribute
bootstrap infrastructure, plus the runtime override flags you can use
without recompiling.

---

## Path A — Run a static seed node

The minimum viable contribution: a long-lived BitAiir node on a static
IP, with the P2P port open to the internet.

### 1. Provision

- A small VPS is enough (1 vCPU, 2 GB RAM, 20 GB SSD).
- Static IPv4 (and IPv6 if available — both A and AAAA records work).
- Open the P2P port in the firewall:
  - **Mainnet**: TCP `8444`
  - **Testnet**: TCP `18444`
- Leave the RPC port (`8443` / `18443`) bound to `127.0.0.1` only.

### 2. Install BitAiir

Either build from source:

```bash
git clone https://github.com/bitaiir/bitaiir.git
cd bitaiir
cargo build --release -p bitaiir-daemon --no-default-features
```

The `--no-default-features` flag drops the TUI and clipboard deps —
smaller binary, no X11/libxcb requirement on the server.

Or pull the Docker image:

```bash
docker run -d --name bitaiir \
    --restart unless-stopped \
    -v bitaiir_data:/data \
    -p 8443:8443 -p 8444:8444 \
    ghcr.io/bitaiir/bitaiir:latest \
    --rpc-addr 0.0.0.0:8443 \
    --p2p-addr 0.0.0.0:8444
```

(For testnet swap the ports and add `--testnet`.)

### 3. Run as a service

The binary itself is a long-running process. Wrap it in a systemd unit
so it restarts on crash and on reboot:

```ini
# /etc/systemd/system/bitaiird.service
[Unit]
Description=BitAiir Core daemon
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/bitaiird --p2p-addr 0.0.0.0:8444
User=bitaiir
Restart=always
RestartSec=10
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now bitaiird
sudo systemctl status bitaiird
```

### 4. Verify the node is reachable

From a different machine:

```bash
nc -vz <your-ip> 8444   # should connect
```

Then from a freshly-started BitAiir node elsewhere:

```bash
bitaiir-cli addpeer <your-ip>:8444
bitaiir-cli listpeers
```

### 5. Submit it as a seed

Once the node has been up for a few weeks with good uptime, open a PR
adding the address to the appropriate array in
`crates/bitaiir-daemon/src/peer_manager.rs`:

```rust
pub const SEED_NODES_MAINNET: &[&str] = &[
    "198.51.100.10:8444",
    "203.0.113.42:8444",
];
```

Include in the PR:

- Operator handle (GitHub username, contact email).
- IP address and how stable it is (months/years).
- Whether IPv6 is available.

---

## Path B — Run a DNS seeder

A DNS seeder is an authoritative DNS server that answers a single
hostname (e.g. `seed.bitaiir.org`) with rotating A/AAAA records of
**healthy** peers it has discovered by crawling the network. New nodes
resolve the hostname, get a fresh batch of IPs, and connect.

DNS seeding is **optional** for early mainnet — Bitcoin shipped without
it for years. But it's the resilience layer you want before the network
grows past a handful of seed operators.

A native Rust `bitaiir-seeder` ships in the workspace — DNS server +
crawler in one binary, reusing `bitaiir-net` for the wire protocol so
it always speaks exactly what the daemon speaks.

Setup (build, DNS delegation, systemd unit, port-53 capabilities,
tuning knobs, monitoring) is documented separately in
[`seeder-operator-guide.md`](./seeder-operator-guide.md).

For mainnet launch and the first months, **Path A** is still enough.
Five to ten static seeds with good uptime bootstrap the network
reliably. DNS seeders are the resilience layer you want once the
network grows past a handful of static-IP operators.

---

## Runtime overrides (no recompile needed)

You don't have to wait for a release to use new seeds. The daemon
accepts seed lists from the config file and the CLI; both are merged
on top of the binary's hardcoded arrays.

### Config file (`bitaiir.toml`)

```toml
[network]
# Static peers tried at startup, on top of the hardcoded list.
seed_nodes = ["198.51.100.10:8444", "198.51.100.11:8444"]

# DNS hostnames re-resolved every hour.
dns_seeds = ["seed.example.org"]

# true = skip DNS resolution entirely (both hardcoded and configured).
# Useful for air-gapped / locked-down deployments.
disable_dns_seeds = false
```

### CLI flags

```bash
bitaiird --seed 198.51.100.10:8444 --seed 198.51.100.11:8444 \
         --dns-seed seed.example.org
```

`--seed` and `--dns-seed` are repeatable and override the config file
when set. `--no-dns-seeds` is the CLI form of `disable_dns_seeds = true`.

### Use cases

- **Private testnet**: empty hardcoded arrays + your own seeds via
  config.
- **Locked-down deployment**: `--no-dns-seeds` + explicit `--connect`
  peers. Daemon never makes a DNS query.
- **Pre-release smoke testing**: try a candidate seed with `--seed`
  before opening a PR to add it to the binary.

### Precedence

```
CLI flag (--seed / --dns-seed / --no-dns-seeds)   ← strongest
config file ([network] seed_nodes / dns_seeds)
hardcoded array (SEED_NODES_* / DNS_SEEDS_*)      ← weakest
```

Lists are **additive**: hardcoded + config + CLI all union (with
duplicates collapsed). The only "subtractive" knob is the
`disable_dns_seeds` / `--no-dns-seeds` boolean, which drops every
DNS seed regardless of source.

---

## Production checklist (before mainnet)

- [ ] At least **2** seed nodes in `SEED_NODES_MAINNET`, ideally 5+.
- [ ] Geographic diversity — not all in one datacenter / AS.
- [ ] Operator contact info recorded (so we can reach you when a seed
      goes down).
- [ ] Each seed verified to accept inbound connections from the open
      internet (test with `nc` or a fresh `bitaiird` from another AS).
- [ ] At least one operator running monitoring (uptime + chain height
      sanity vs the network majority).
- [ ] Optional but nice: at least one `DNS_SEEDS_MAINNET` entry backed
      by a working seeder.

Testnet has a lower bar — one or two seeds is fine.
