# Faucet Operator Guide

Running a public testnet faucet so other developers can pull AIIR
without mining their own.

`bitaiir-faucet` is a small HTTP service that **does not hold keys**.
It talks to a local `bitaiird --testnet` over JSON-RPC and asks the
daemon to `sendtoaddress` from its own wallet. The operator pre-funds
that wallet (by mining or by manual transfer) and the faucet relays
small amounts to anyone who hits `POST /drip`.

---

## Quick start

```bash
# 1. Run a testnet daemon (and let it mine until you have a balance).
./target/release/bitaiird --testnet --mine

# 2. In another terminal, start the faucet.
./target/release/bitaiir-faucet \
    --listen 127.0.0.1:8090 \
    --drip-amount 10 \
    --cooldown-secs 86400 \
    --max-per-ip 5

# 3. From a third terminal, ask for a drip.
curl -X POST http://127.0.0.1:8090/drip \
     -H 'Content-Type: application/json' \
     -d '{"address":"aiir1Bvkd9SeDDtXekj7RifZ3dCXaHnV6mAXZv"}'
# → {"from":"aiir1...","to":"aiir1Bvkd9...","amount":"10 AIIR",
#    "change":"...","priority":1,"peers_notified":N,
#    "status":"accepted for mining (tx-pow + broadcast happen in background)"}
```

The response mirrors the daemon's `sendtoaddress` output verbatim;
`sendtoaddress` is fire-and-forget so there's no `txid` yet — the
node mines the tx-PoW in the background and broadcasts when it's
done.  Watch the daemon log for the `send_to_address: tx ...
broadcast to N peer(s)` line that confirms completion.

If the daemon uses config-based RPC auth (`[rpc] user`/`password` set
in `bitaiir.toml`) you have to pass them explicitly:

```bash
./target/release/bitaiir-faucet \
    --rpc-user admin --rpc-password senha123
```

When the daemon uses cookie auth (the default), the faucet reads
`<data_dir>/.cookie` automatically — same as `bitaiir-cli`.

---

## Endpoints

| Method | Path      | Description |
|--------|-----------|-------------|
| GET    | `/`       | One-line description for browser visitors. |
| GET    | `/info`   | JSON: `drip_amount`, `cooldown_secs`, `max_per_ip`, `priority`. |
| GET    | `/health` | `"ok"` (200) or daemon error (503). |
| POST   | `/drip`   | Body `{"address": "aiir1..."}`. Returns the txid on success, a 429 / 4xx with `retry_after` on rate-limit, or a 502 if the daemon refuses (insufficient balance, etc.). |

Example success (the daemon's `sendtoaddress` payload, returned
verbatim — no `txid` yet because tx-PoW mining is fire-and-forget):

```json
{
  "from": "aiir1DGc48AvtcSZqyBGvzY4GSK8fAVEH2gE8U",
  "to": "aiir1Bvkd9SeDDtXekj7RifZ3dCXaHnV6mAXZv",
  "amount": "10.00000000 AIIR",
  "change": "...",
  "priority": 1,
  "peers_notified": 1,
  "status": "accepted for mining (tx-pow + broadcast happen in background)"
}
```

Example rate-limit:

```json
{
  "error": "address recently drained from this faucet",
  "retry_after": 73821
}
```

---

## Rate limiting

Two independent in-memory limits (both reset when the faucet
restarts; persistence is a deliberate non-goal):

1. **Per address** — one drip per recipient address per
   `--cooldown-secs` (default 24 hours).
2. **Per source IP** — at most `--max-per-ip` drips per cooldown
   window (default 5 / 24h).

Total faucet exposure is therefore bounded by:

```
max_loss_per_window = drip_amount × max_per_ip × distinct_ips
```

For abusive load, set `--cooldown-secs 86400 --max-per-ip 1`. For
a more relaxed dev network, `--cooldown-secs 3600 --max-per-ip 10`.

---

## Production deployment

### Reverse proxy (recommended)

Bind the faucet to localhost and put it behind nginx / Caddy with
TLS and a public hostname:

```nginx
server {
    listen 443 ssl;
    server_name faucet.bitaiir.org;

    ssl_certificate     /etc/letsencrypt/live/faucet.bitaiir.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/faucet.bitaiir.org/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8090;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

> **Note**: the current rate-limiter keys on the TCP source IP it
> sees, which behind a proxy is the proxy's IP. If you deploy
> behind nginx, either trust your proxy and bind the faucet on
> `0.0.0.0` directly, or wait for honoring `X-Forwarded-For` (open
> issue / contribute a PR).

### systemd unit

```ini
# /etc/systemd/system/bitaiir-faucet.service
[Unit]
Description=BitAiir testnet faucet
After=bitaiird.service
Requires=bitaiird.service

[Service]
ExecStart=/usr/local/bin/bitaiir-faucet \
    --listen 127.0.0.1:8090 \
    --rpc-url https://127.0.0.1:18443 \
    --data-dir /var/lib/bitaiir/testnet
User=bitaiir
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Topping up

The faucet's "balance" is whatever spendable AIIR the daemon's wallet
has. Monitor it with:

```bash
bitaiir-cli --testnet --rpc-user ... --rpc-password ... listaddresses
```

To pre-fund: enable mining on the daemon for a while (`/mine-start`),
or transfer in from another testnet wallet.

When `sendtoaddress` starts returning `insufficient spendable
balance`, the faucet returns 502 to clients; top the wallet up and
service resumes automatically.

---

## Limitations

- **No persistence** of rate-limit state — a restart wipes the
  cooldown table. If you need durable abuse tracking, run the faucet
  behind a reverse proxy that does its own rate-limiting on top.
- **Single source IP per request** — the faucet trusts the TCP peer
  IP. Adding `X-Forwarded-For` honoring is straightforward; PR
  welcome if you need it before the upstream change lands.
- **No CAPTCHA / anti-bot** — testnet abuse is bounded by the
  operator's funding choice, not by client identity. Mainnet faucets
  are not a goal of this crate.
