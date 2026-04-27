# DNS Seeder Operator Guide

Running `bitaiir-seeder` — an authoritative DNS server that crawls the
BitAiir P2P network and serves the top-N healthy peers as A records.

This is the doc for operators who want to host `seed.example.org` and
have new BitAiir nodes resolve that hostname into a fresh batch of
healthy peers. For static-IP seed nodes (the simpler path), see
[`seed-operator-guide.md`](./seed-operator-guide.md).

---

## What it does

`bitaiir-seeder` is one binary running three concurrent tasks against a
shared on-disk peer database:

1. **Crawler** — connects to known peers, runs the BitAiir handshake
   and `getaddr`, learns more peers from the gossip reply, and records
   success / failure stats per peer.
2. **DNS authoritative server** — answers `<zone> IN A` queries with
   up to 16 A records of peers that succeeded recently and have a
   reasonable success-to-failure ratio.
3. **Persistence** — single-file redb database holding discovery
   timestamps, attempt history, and the most recent height + user-agent
   we got back from each peer.

Wire protocol is BitAiir's own (handshake → `getaddr` → `addr`),
implemented via the `bitaiir-net` crate the daemon also uses, so the
seeder always speaks exactly what `bitaiird` speaks.

The DNS half is built on `hickory-dns-server` and answers UDP only.
TCP fallback and AAAA records are out of scope for v0.1.x — peers we
crawl over IPv4 store IPv4 socket addresses, and adding IPv6 means
crawling over IPv6 as well, not just answering AAAA queries.

---

## Prerequisites

- A small VPS (1 vCPU, 1 GB RAM, 5 GB SSD is plenty).
- A static public IPv4.
- A domain you control, with the ability to add NS / A records at the
  registrar.
- BitAiir source checkout or a release binary.
- Linux, macOS, or Windows. The examples below assume Linux + systemd.

---

## 1. Build

```bash
git clone https://github.com/bitaiir/bitaiir.git
cd bitaiir
cargo build --release -p bitaiir-seeder
```

The output is `target/release/bitaiir-seeder` (`.exe` on Windows).

---

## 2. DNS delegation

The seeder is authoritative for **one hostname** (the zone). Two
common shapes:

### Apex hostname (operator owns the domain)

```
example.org.            NS    seeder.example.org.
seeder.example.org.     A     198.51.100.42
```

Then run the seeder with `--zone example.org`.

### Subdomain (operator gets a delegated zone)

```
seed.bitaiir.org.       NS    seeder.example.org.
seeder.example.org.     A     198.51.100.42
```

Run with `--zone seed.bitaiir.org`. This is the typical contributor
path: the BitAiir maintainers add the NS record at the parent zone,
the operator runs the seeder.

The seeder answers **only** for the zone you pass via `--zone`.
Queries for any other name return REFUSED.

---

## 3. Run

The seeder needs at least one initial peer to bootstrap. After the
first round it self-discovers more via `getaddr`, but the very first
crawl needs a starting point.

```bash
bitaiir-seeder \
    --zone seed.bitaiir.org \
    --dns-listen 0.0.0.0:5353 \
    --seed 198.51.100.10:8444 \
    --seed 198.51.100.11:8444 \
    --data-dir /var/lib/bitaiir-seeder
```

Mainnet uses port `8444`; for testnet add `--testnet` and use port
`18444` on the seed peers.

### Why `:5353` and not `:53`?

Port 53 is privileged on Linux — binding it from a non-root process
needs `CAP_NET_BIND_SERVICE`. The CLI default is `127.0.0.1:5353` so
development just works. For production, see the section below.

---

## 4. Production: bind on port 53

Two clean options on Linux:

### Option A — `setcap` (recommended)

Grant the binary the one capability it needs:

```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/bitaiir-seeder
```

Then run as a non-root user with `--dns-listen 0.0.0.0:53`.

### Option B — systemd `AmbientCapabilities`

```ini
# /etc/systemd/system/bitaiir-seeder.service
[Unit]
Description=BitAiir DNS seeder
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/bitaiir-seeder \
    --zone seed.bitaiir.org \
    --dns-listen 0.0.0.0:53 \
    --seed 198.51.100.10:8444 \
    --seed 198.51.100.11:8444 \
    --data-dir /var/lib/bitaiir-seeder
User=bitaiir-seeder
Group=bitaiir-seeder
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/bitaiir-seeder
ProtectHome=true
PrivateTmp=true
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -s /usr/sbin/nologin bitaiir-seeder
sudo install -d -o bitaiir-seeder -g bitaiir-seeder /var/lib/bitaiir-seeder
sudo systemctl enable --now bitaiir-seeder
```

---

## 5. Verify

From any machine:

```bash
dig +short seed.bitaiir.org @<your-ip>
```

You should see up to 16 A records. The first time you run, it will be
empty (the crawler hasn't gathered any healthy peers yet). Wait one or
two crawl rounds (~20 s each) and try again.

To check from the public DNS resolution path (i.e. via the NS record):

```bash
dig +short seed.bitaiir.org
```

This goes via your registrar / parent zone; if it returns nothing,
double-check the NS delegation.

---

## 6. Tuning knobs

The defaults are tuned for "small operator, medium scale". Source-level
constants in `crates/bitaiir-seeder/src/`:

| Constant            | Default | Where        | What it controls                                  |
|---------------------|---------|--------------|----------------------------------------------------|
| `DNS_RESPONSE_MAX`  | 16      | `dns.rs`     | Max A records per reply (fits a 512-byte UDP).     |
| `DNS_RECENT_SECS`   | 1800    | `dns.rs`     | "Recent enough" window for serving a peer.         |
| `DNS_TTL_SECS`      | 60      | `dns.rs`     | TTL on each A record.                              |
| `CRAWL_BATCH`       | 64      | `crawler.rs` | Peers attempted per round.                         |
| `CRAWL_PARALLELISM` | 16      | `crawler.rs` | Max concurrent connections.                        |
| `ROUND_INTERVAL`    | 20 s    | `crawler.rs` | Sleep between rounds.                              |
| `CRAWL_COOLDOWN`    | 5 min   | `crawler.rs` | Min spacing between attempts on the same peer.     |

These are constants, not flags — change them by editing the source and
rebuilding. The defaults are fine for running a public seeder for
mainnet or testnet from a small VPS.

---

## 7. Submitting your seeder to the network

Once your seeder has been up for a few weeks with healthy uptime, open
a PR adding it to `DNS_SEEDS_MAINNET` in
`crates/bitaiir-daemon/src/peer_manager.rs`:

```rust
pub const DNS_SEEDS_MAINNET: &[&str] = &[
    "seed.example.org",
    "seed.bitaiir.org",
];
```

In the PR:

- Operator handle (GitHub username, contact email).
- The hostname and how it's delegated.
- Confirmation that the DNS server has been answering for 2+ weeks.

---

## 8. Health and monitoring

The seeder logs to stderr. Useful structured fields under
`tracing-subscriber`:

```
target=seeder.crawler attempts=64 known=312 "crawling round"
target=seeder.dns zone=seed.bitaiir.org listen=0.0.0.0:53 "DNS server listening"
```

For monitoring, the basics are:

- **Uptime** — `systemctl is-active bitaiir-seeder`.
- **DNS responses** — `dig +short <zone>` should return at least 1 A
  record, ideally 5+ during normal operation.
- **DB size** — `du -h /var/lib/bitaiir-seeder/seeder.mainnet.redb`.
  Should grow modestly (one row per peer ever discovered) and plateau
  around the network's reachable peer count.

A full Prometheus exporter is not in v0.1.x. If you want metrics, run
the seeder behind a sidecar that scrapes the log stream.

---

## 9. Anti-spam considerations

The DNS server answers any A query for the configured zone. There is
no per-source rate limit yet — that's the resolver's job (the seeder
is upstream of recursive resolvers, not end clients).

If you operate a high-traffic seeder and start seeing abuse, the
typical countermeasures live in front of the seeder, not inside it:

- A small UDP rate limiter (`iptables`, `nftables`, or `unbound` as a
  shield).
- DDoS-protected DNS hosting (Cloudflare, AWS Route 53) with the
  seeder as a hidden secondary — but this means trusting the provider
  with the answer set.

For mainnet launch volumes, none of this is needed.

---

## 10. Shutdown

The seeder traps `SIGINT` (Ctrl-C). On signal it stops accepting new
DNS queries, drains in-flight ones, and exits cleanly. The redb file
is ACID and safe to copy / back up while the process is stopped — no
WAL recovery needed.
