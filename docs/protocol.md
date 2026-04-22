# BitAiir Protocol Specification

**Version:** 1
**Status:** Draft — subject to change until the genesis block is mined and published.
**Last updated:** 2026-04-21

This document records the consensus parameters of the BitAiir cryptocurrency
protocol. Anything not listed here is an implementation detail and may be
changed by any implementation without breaking compatibility; anything
listed here is a consensus rule that cannot be changed without a hard
fork.

Status labels for individual values:

- **(decided)** — final for protocol version 1.
- **(provisional)** — current best guess, may still change before the
  genesis block is mined.
- **(open)** — not yet settled, needs explicit sign-off before mainnet.

---

## 0. Design goals

BitAiir is a **payment cryptocurrency**, not a store of value. It takes
cues from both Bitcoin (proof of work, decentralization, open
participation) and Brazil's Pix instant-payment system (fast, low-fee,
accessible to everyone). The concrete goals below should be used to
resolve any design ambiguity in the rest of the document:

1. **Fast confirmations.** A payment should feel "done" within seconds
   from the payer's perspective, not minutes or hours. The target block
   time is 5 seconds, and wallets are expected to treat 1 confirmation
   as sufficient for everyday payments.
2. **Zero fees by default.** Transactions have no mandatory fee. A
   sender can voluntarily include a tip to incentivize faster
   inclusion, but the protocol does not reject fee-free transactions.
3. **Mining must be accessible.** Anyone who can run the daemon should
   be able to mine blocks. The proof-of-work algorithm is deliberately
   hostile to ASIC and GPU acceleration (see section 9) so that a
   commodity CPU remains competitive throughout the project's lifetime.
4. **Decentralized issuance, forever.** There is no pre-mine, no
   foundation allocation, no ICO. New coins enter circulation only via
   the coinbase transaction of each mined block. Issuance does not stop
   — there is a fixed tail emission so that mining always pays (see
   section 4.2).
5. **Anti-spam without fees.** Because fees are zero, transactions
   themselves include a small proof of work that costs the sender
   roughly two seconds of CPU time (section 7.7). This makes flood
   attacks uneconomical without charging honest users money.
6. **Mobile users can pay; desktop users mine.** The protocol does not
   block mobile mining, but the ecosystem realities (app-store policies,
   thermal throttling, battery drain) mean mobile is a first-class
   platform for wallets and a second-class platform for miners. See
   section 19 for the rationale.
7. **Implementation simplicity in v1.** Where two designs are equally
   valid, the one that is simpler to implement, test, and audit wins.
   We can always add complexity later; we cannot safely remove it.

---

## 1. Overview

BitAiir is a Bitcoin-style UTXO cryptocurrency with a payment-first
design:

- Account state is a set of unspent transaction outputs (UTXOs), not a
  ledger of balances.
- Transactions consume previous outputs and create new ones.
- There is no on-chain scripting language in version 1. Spending an
  output requires a `(signature, public_key)` pair that hashes (via
  HASH160) to the output's `recipient_hash`.
- Consensus is achieved via proof of work. The work function, called
  **Proof of Aiir**, wraps the Bitcoin-family `double_sha256` primitive
  in an Argon2id memory-hard step that bounds ASIC acceleration
  (section 9). In code the corresponding function is written
  `aiir_pow()` for Rust-identifier friendliness.
- New coins are issued via the coinbase transaction of each block,
  following a halving schedule that bottoms out at a permanent tail
  emission (section 4).
- Transactions carry a small embedded proof of work as a spam
  mitigation, replacing the fee-based anti-spam of Bitcoin
  (section 7.7). Senders may declare a higher-than-minimum priority by
  paying proportionally more CPU work; the mempool orders deterministically
  by declared priority.
- Two parallel networks — **mainnet** and **testnet** — share the
  protocol code but diverge in magic bytes, ports, coinbase maturity,
  and genesis (section 3).

All cryptographic primitives, address formats, and signed-message rules
are shared with Bitcoin's lineage, with BitAiir-specific identifiers so
a BitAiir artifact cannot be confused with a Bitcoin artifact.

---

## 2. Constants table

| Name                           | Value (mainnet / testnet)                    | Status       |
| ------------------------------ | -------------------------------------------- | ------------ |
| Protocol version               | 1                                            | decided      |
| Network magic bytes            | `0xB1 0x7A 0x11 0xED` / `0xB1 0x7A 0x11 0x7E`| provisional  |
| Default P2P port               | 8444 / 18444                                 | provisional  |
| Default RPC port               | 8443 / 18443                                 | provisional  |
| Default data directory         | `bitaiir_data` / `bitaiir_testnet_data`      | provisional  |
| Coinbase maturity              | 100 blocks / 10 blocks                       | provisional  |
| Address prefix (string)        | `"aiir"`                                     | decided      |
| Address version byte           | `0x00`                                       | decided      |
| WIF version byte               | `0xfe`                                       | decided      |
| BIP44 coin type                | `8888'` (unregistered placeholder)           | provisional  |
| Signed message prefix          | `"BitAiir Signed Message:\n"`                | decided      |
| Atomic units per whole AIIR    | 100_000_000 (10^8)                           | decided      |
| Initial block reward           | 100 AIIR                                     | provisional  |
| Blocks per halving             | 50_000_000                                   | provisional  |
| Tail emission floor            | 10 AIIR / block                              | provisional  |
| Approximate long-term supply   | ~11.26 billion AIIR at year 100              | provisional  |
| Target block time              | 5 seconds                                    | provisional  |
| Difficulty retarget interval   | 20 blocks                                    | provisional  |
| Max difficulty adjustment      | 4× per retarget                              | provisional  |
| Initial difficulty `bits`      | `0x2000ffff`                                 | provisional  |
| Proof of work                  | Proof of Aiir (SHA-256d + Argon2id wrap)     | provisional  |
| Argon2id memory cost           | 65_536 KiB (64 MiB)                          | provisional  |
| Argon2id time cost             | 1 iteration                                  | provisional  |
| Argon2id parallelism           | 1 lane                                       | provisional  |
| Argon2id output length         | 32 bytes                                     | provisional  |
| Tx-level anti-spam PoW target  | ~2 s CPU time on commodity laptop            | provisional  |
| Minimum tx priority            | 1                                            | provisional  |
| Max serialized block size      | 1_000_000 bytes                              | provisional  |
| Max serialized transaction size| 100_000 bytes                                | provisional  |
| Default mempool size cap       | 50 MB                                        | provisional  |
| Locktime semantics             | block height only (no timestamp mode)        | provisional  |
| Time-past-median window        | 11 blocks                                    | provisional  |
| Max headers per P2P message    | 2000                                         | provisional  |
| Max block locator entries      | 64                                           | provisional  |
| Max addresses per `addr` msg   | 1000                                         | provisional  |

---

## 3. Networks — mainnet and testnet

BitAiir ships with two parallel networks that share the same consensus
code but diverge in the few parameters needed to keep them
cryptographically and operationally isolated. A single process runs on
exactly one network, chosen at startup via the `--testnet` CLI flag or
the `network.testnet = true` config option.

### 3.1 Parameters that differ

| Parameter               | Mainnet                     | Testnet                     |
| ----------------------- | --------------------------- | --------------------------- |
| Network magic bytes     | `0xB1 0x7A 0x11 0xED`       | `0xB1 0x7A 0x11 0x7E`       |
| Default P2P port        | 8444                        | 18444                       |
| Default RPC port        | 8443                        | 18443                       |
| Default data directory  | `bitaiir_data`              | `bitaiir_testnet_data`      |
| Coinbase maturity       | 100 blocks                  | 10 blocks                   |
| Genesis burn phrase     | `"BitAiir Genesis Burn"`    | `"BitAiir Testnet Genesis Burn"` |
| Genesis coinbase message| see section 16.1            | `"BitAiir Testnet Genesis"` |
| Genesis timestamp (UTC) | 2026-03-29 00:00:00         | 2026-04-06 00:00:00         |

### 3.2 Parameters that are shared

Everything not in the table above — tokenomics, Proof of Aiir
parameters, canonical encoding, address format, WIF, signed-message
prefix, block size cap, transaction size cap, difficulty retarget
interval, target block time, tx-PoW anti-spam target, mempool
ordering, fork-choice rule — is identical on both networks. An
implementation supports both networks by toggling the short list of
divergent parameters from a single `Network` enum.

### 3.3 Isolation rationale

- Different **magic bytes** mean a mainnet node ignores every byte a
  testnet node sends and vice versa; they cannot form a peer connection
  even if accidentally wired to each other.
- Different **ports** keep the two networks' default sockets from
  colliding on a host that runs both.
- Different **data directories** let one machine keep mainnet and
  testnet chains side by side without any cross-contamination of blocks
  or UTXO sets.
- Different **genesis parameters** mean the two chains start from
  cryptographically distinct roots; no amount of mining can make a
  mainnet block valid on testnet.
- **Shorter coinbase maturity** on testnet (10 vs 100 blocks) lets
  developers test end-to-end payment flows without waiting for a
  long coinbase maturity window.

### 3.4 Network defaulting

If a client or tool does not explicitly set the network, it defaults
to **mainnet**. Daemon startup prints the active network name so it
cannot be mistaken.

---

## 4. Tokenomics

### 4.1 Atomic units

BitAiir uses 8 decimal places of precision. The smallest representable
quantity is one hundred-millionth of an AIIR:

```
1 AIIR = 100_000_000 atomic units
```

All on-chain amounts are stored and transmitted as `u64` counts of
atomic units. This follows Bitcoin's satoshi convention and matches the
`Amount` newtype in `bitaiir-types`.

### 4.2 Supply schedule — halvings plus tail emission

BitAiir does not have a hard cap on total supply. Instead, emission has
two phases:

**Phase 1: geometric halvings.** The block subsidy starts at
**100 AIIR** and halves every **50,000,000 blocks**. At the target
block time of 5 seconds this is approximately 7.9 years per halving.

```
subsidy_phase1(height) = 100 AIIR / 2 ^ (height / 50_000_000)
```

**Phase 2: tail emission.** When the halving curve would take the
subsidy below the tail floor of **10 AIIR per block**, it stops
halving and stays at 10 AIIR forever.

```
subsidy(height) = max(subsidy_phase1(height), 10 AIIR)
```

Concretely, the halving schedule is:

| Era | Block range              | Subsidy          | Approx. years |
| --- | ------------------------ | ---------------- | ------------- |
| 1   | 0 .. 50,000,000          | 100 AIIR         | 0 – 7.9       |
| 2   | 50,000,000 .. 100,000,000  | 50 AIIR          | 7.9 – 15.9    |
| 3   | 100,000,000 .. 150,000,000 | 25 AIIR          | 15.9 – 23.8   |
| 4   | 150,000,000 .. 200,000,000 | 12.5 AIIR        | 23.8 – 31.7   |
| 5+  | 200,000,000 .. ∞           | **10 AIIR (floor)** | 31.7+     |

From block `200,000,000` onward, the subsidy is exactly 10 AIIR per
block for the rest of the chain's existence.

**Total supply at key milestones** (rounded):

- End of Era 1: 5.000 B AIIR mined
- End of Era 2: 7.500 B AIIR mined
- End of Era 3: 8.750 B AIIR mined
- End of Era 4: 9.375 B AIIR mined
- Tail-emission steady state: ~**63 M AIIR added per year**

**Inflation rate at steady state** (approximate):

- Year 32 (tail emission just started, supply ~9.4 B): 63 M / 9.4 B ≈ **0.67 % / yr**
- Year 50 (supply ~10.5 B): 63 M / 10.5 B ≈ **0.60 % / yr**
- Year 100 (supply ~13.7 B): 63 M / 13.7 B ≈ **0.46 % / yr**

The tail-emission rate is a **fixed absolute amount**, not a
percentage, so the inflation rate declines monotonically as the supply
grows. There is no point at which inflation stops, but it converges
asymptotically toward zero. This mirrors Monero's 2018 tail-emission
design.

### 4.3 Rationale for tail emission

BitAiir is a payment currency, not a store of value. Continuous modest
emission:

- Guarantees miners always have a subsidy, even after fee-less block
  space stops rewarding them through fees (because there are no fees
  in BitAiir — see section 7.6).
- Encourages spending over hoarding, which is the correct incentive
  for a medium of exchange.
- Matches real-world fiat behavior (central banks target 2–3 %
  inflation); 0.5 % is well below that and nearly imperceptible in
  daily use.
- Removes the "fee-market cliff" that Bitcoin will face post-2140.

### 4.4 Rounding

Halvings are performed as a right-shift on the **atomic-unit** value
of the subsidy, not on the human-readable AIIR amount. Because one
AIIR is 10^8 atomic units and that factor already contains eight
factors of two, the four halvings from era 1 to era 4 land on exactly
representable values with no rounding at all:

```text
era 1: 10_000_000_000 atoms   = 100   AIIR
era 2:  5_000_000_000 atoms   =  50   AIIR
era 3:  2_500_000_000 atoms   =  25   AIIR
era 4:  1_250_000_000 atoms   =  12.5 AIIR
```

From era 5 onward the tail emission floor takes over at 10 AIIR per
block before any right-shift would drop an odd atomic unit, so the
entire subsidy schedule is exact in `u64`. In particular, era 4 pays
exactly 12.5 AIIR, never a rounded-down 12.

The tail-emission floor of 10 AIIR is chosen to be a round number
rather than the exact geometric value, to keep the schedule easy to
reason about for users.

---

## 5. Addresses

### 5.1 Format

A BitAiir address is the ASCII string `"aiir"` concatenated with the
Base58Check encoding of a 21-byte payload:

```
address = "aiir" + base58check(version_byte || hash160(public_key))
```

Where:

- `version_byte` is `0x00` (address version byte, decided).
- `hash160(x) = ripemd160(sha256(x))`.
- `base58check` appends a 4-byte SHA-256d checksum, then encodes using
  the Bitcoin Base58 alphabet.

The literal `"aiir"` prefix is **not** part of the checksummed payload.
Decoders strip the prefix before verifying the Base58Check body.

### 5.2 WIF (Wallet Import Format)

Private keys exported as WIF use the version byte `0xfe` (distinct from
Bitcoin mainnet `0x80` and testnet `0xef`), followed by the 32-byte
private key, followed by an optional compression flag `0x01`, all
passed through Base58Check:

```
wif_uncompressed = base58check(0xfe || privkey)
wif_compressed   = base58check(0xfe || privkey || 0x01)
```

The same WIF version byte is used on both mainnet and testnet; address
isolation comes from the address version byte and the network magic,
not from the WIF prefix.

---

## 6. Signed messages

Message signing follows Bitcoin's `signmessage` format with a
BitAiir-specific magic string:

```
magic_bytes   = varint(len(PREFIX)) || PREFIX ||
                varint(len(message)) || message
digest        = double_sha256(magic_bytes)
signature     = ecdsa_sign_rfc6979(privkey, digest)
header_byte   = 27 + recovery_id + (4 if compressed else 0)
serialized    = base64(header_byte || r || s)
```

Where `PREFIX = "BitAiir Signed Message:\n"` (24 bytes).

Signatures are 65 bytes pre-base64: 1 byte header, 32 bytes `r`,
32 bytes `s`. Signers must use RFC 6979 deterministic nonces and the
low-`s` canonical form (BIP 62).

---

## 7. Transactions

### 7.1 Model

BitAiir is a UTXO chain. A transaction consumes a set of previously
unspent outputs (the inputs) and creates a new set of unspent outputs.
The transaction is valid only if:

- Every input references a previous `(txid, vout)` that exists and is
  unspent.
- Every input's `(signature, pubkey)` pair authorizes the referenced
  output (the HASH160 of `pubkey` matches `recipient_hash`, and the
  ECDSA signature over the sighash is valid under `pubkey`).
- `sum(input_amounts) ≥ sum(output_amounts)` (no money is created).
- No output value exceeds the current subsidy cap plus circulating
  supply bounds.
- The serialized transaction is at most `MAX_TX_SIZE` bytes.
- The transaction's `locktime` is satisfied at the block it is being
  included in.
- The transaction's `pow_priority` is at least `1`.
- The transaction's embedded `pow_nonce` satisfies the anti-spam proof
  of work at the declared priority (section 7.7).

Transactions may have a fee of **zero** atomic units. Fees are
explicitly optional (section 7.6).

### 7.2 Structure

A transaction is the following Rust struct, serialized with the
canonical encoding defined in section 10:

```rust
struct Transaction {
    version: u32,
    inputs: Vec<TxIn>,
    outputs: Vec<TxOut>,
    locktime: u32,
    pow_nonce: u64,         // anti-spam PoW nonce, see section 7.7
    pow_priority: u64,      // declared mempool priority, see section 7.7
}

struct TxIn {
    prev_out: OutPoint,     // txid + vout
    signature: Vec<u8>,     // 64-byte compact ECDSA signature, or coinbase payload
    pubkey: Vec<u8>,        // 33 or 65 bytes; empty for coinbase
    sequence: u32,
}

struct TxOut {
    amount: Amount,         // u64 atomic units
    recipient_hash: [u8; 20],
}

struct OutPoint {
    txid: Hash256,
    vout: u32,
}
```

### 7.3 Txid

A transaction's ID is the `double_sha256` of its canonical serialization,
including signatures, `pow_nonce`, and `pow_priority`. Re-signing the
same transaction under a different nonce would change its txid; this is
prevented because BitAiir requires RFC 6979 deterministic signatures,
which are a pure function of the private key and the sighash.

### 7.4 Sighash

The digest signed by a `TxIn` is computed by:

1. Cloning the transaction.
2. Clearing the `signature` field of every input to an empty `Vec<u8>`.
3. Clearing the `pow_nonce` field to `0`.
4. Clearing the `pow_priority` field to `0`.
5. Leaving the `pubkey` field of every input intact.
6. Serializing the result with the canonical encoding.
7. Hashing with `double_sha256`.

Clearing `pow_nonce` **and** `pow_priority` in the sighash is important:
otherwise the sender would have to re-sign after mining the anti-spam
PoW or after changing priority, which would create a chicken-and-egg
problem between signing and spam mitigation.

This is the simplest possible sighash scheme. It signs all inputs and
all outputs (equivalent to Bitcoin's `SIGHASH_ALL`) and does not support
any other sighash flags.

### 7.5 Coinbase

The first transaction in every block must be a coinbase. It has:

- Exactly one input with `prev_out = (Hash256::ZERO, u32::MAX)`.
- The `signature` field of that input is free-form and is used by
  miners as an extra-nonce / tagging area.
- The `pubkey` field of that input is empty.
- `pow_nonce = 0` and `pow_priority = 1` (coinbase transactions are
  exempt from the anti-spam PoW; they are already bounded by the
  block's own PoW).
- Arbitrarily many outputs.
- `sum(outputs) ≤ subsidy(block_height) + sum(fees_in_block)`.

Where `fees_in_block` is the sum of all voluntary fees in non-coinbase
transactions included in the block.

Outputs created by a coinbase transaction mature after
**`coinbase_maturity(network)` blocks** (100 on mainnet, 10 on testnet
— see section 3). A transaction that spends an immature coinbase
output is rejected.

### 7.6 Fees

The protocol imposes **no minimum fee**. A transaction is valid even
when `sum(input_amounts) == sum(output_amounts)`, i.e. when the
sender keeps no change for the miner.

A sender may voluntarily include a fee by making the output total less
than the input total. The difference is claimed by the block's coinbase
transaction. Miners are free to prioritize higher-fee transactions when
selecting from the mempool, but are not required to — the mempool
ordering policy is a local choice, not a consensus rule. The reference
implementation orders by **declared priority** (section 7.7), not by
fee.

Because the block subsidy never falls below 10 AIIR (tail emission),
mining is always profitable even when every transaction in the block
has zero fee.

### 7.7 Anti-spam proof of work and declared priority

Every non-coinbase transaction must carry a proof of work over its own
contents to prevent flood attacks. The sender computes this PoW once,
at send time, before broadcasting the transaction.

**Minimum target.** The tx-level PoW has a fixed minimum target
`MIN_TX_TARGET` that a commodity laptop CPU can meet in approximately
**2 seconds** with priority `1`. The exact numerical minimum target is
part of the protocol and is calibrated before mainnet. A provisional
value is
`0x0000_000f_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff`,
meaning the first four bytes of the digest must be zero.

**Declared priority.** Each transaction carries a `pow_priority: u64`
field declaring how much harder-than-minimum the sender committed to
mining. The effective target is:

```
effective_target(tx) = MIN_TX_TARGET / max(tx.pow_priority, 1)
```

Priority `1` is the minimum and corresponds to baseline ~2 s of CPU
work. Priority `N` requires roughly `N`× the CPU work (~2 N seconds).
Priority `0` is treated as `1` by the target formula and is rejected
at validation time.

**Computation** (sender side, after signatures are produced):

```
fn compute_tx_pow(tx: &mut Transaction, priority: u64) {
    tx.pow_priority = priority.max(1);
    let target = MIN_TX_TARGET / U256::from(tx.pow_priority);

    let tx_digest = {
        // Hash the transaction with pow_nonce temporarily set to zero.
        let mut canonical = tx.clone();
        canonical.pow_nonce = 0;
        double_sha256(canonical_encode(&canonical))
    };

    for nonce in 0u64.. {
        let attempt = double_sha256(&[&tx_digest[..], &nonce.to_le_bytes()].concat());
        if attempt_as_u256(attempt) <= target {
            tx.pow_nonce = nonce;
            return;
        }
    }
}
```

**Verification** recomputes `effective_target(tx)` from the declared
`pow_priority` and checks that the PoW hash meets it. The check is two
`double_sha256` calls plus one division — trivially cheap for nodes.
A sender cannot falsely claim priority `N` without actually mining
against the proportionally-stricter target, because validation
enforces the declared target.

**Mempool ordering.** Mempools order by `pow_priority` **descending**
(highest priority first), with arrival order as a deterministic
tiebreaker (oldest arrival first). This makes tx ordering predictable
across nodes and matches the sender's declared willingness to spend
CPU for faster confirmation. See section 13 for the full mempool
policy.

**Security property.** A spammer who wants to submit `N` transactions
per second at priority `1` must spend `2 × N` CPU-seconds of work per
second. A single-core attacker is capped at ~0.5 tx/s. Breaking 1000
tx/s requires 2000 cores running continuously, which is economically
unattractive for spam purposes. Declaring high priority costs the
attacker proportionally more work, so priority cannot be used as a
spam amplifier.

**Coinbase exemption.** Coinbase transactions carry `pow_nonce = 0`
and `pow_priority = 1`. They are not spam vectors because block
production is already rate-limited by the main (Proof of Aiir) proof of
work.

---

## 8. Blocks

### 8.1 Structure

```rust
struct BlockHeader {
    version: u32,
    prev_block_hash: Hash256,
    merkle_root: Hash256,
    timestamp: u64,        // seconds since Unix epoch
    bits: u32,             // compact difficulty target
    nonce: u32,
}

struct Block {
    header: BlockHeader,
    transactions: Vec<Transaction>,
}
```

### 8.2 Block hash

The block hash is `aiir_pow(canonical_encode(BlockHeader))`, where
`aiir_pow` is the Rust name of the Proof-of-Aiir function defined in
section 9. A block is valid only if its hash, interpreted as a 256-bit
little-endian integer, is less than or equal to the target encoded by
`bits`.

The block hash is used both as the block's identity (the value stored
in the next block's `prev_block_hash`) and as the proof-of-work check
— just as in Bitcoin.

### 8.3 Merkle root

The `merkle_root` field must equal `merkle_root(tx_ids)` where `tx_ids`
is the ordered list of transaction IDs in the block, and `merkle_root`
is the Bitcoin-style pairwise `double_sha256` reduction. If a level has
an odd number of hashes, the last one is duplicated.

This inherits CVE-2012-2459 by construction. The mitigation is the
consensus rule **"a valid block must not contain duplicate
transactions"**, enforced by `bitaiir-chain` at validation time.

### 8.4 Validation rules

A block is valid if and only if all of the following hold:

1. Its serialized size is at most `MAX_BLOCK_SIZE` bytes.
2. Its header hash `aiir_pow(header_bytes)` is numerically ≤ the target
   encoded by `bits`.
3. Its `bits` field equals the value expected from the difficulty
   adjustment algorithm (section 9.4).
4. Its `timestamp` is strictly greater than the median timestamp of
   the previous 11 blocks.
5. Its `timestamp` is at most 2 hours in the future relative to the
   validating node's adjusted network time.
6. Its `prev_block_hash` equals the header hash of the block it builds
   on.
7. Its `merkle_root` equals the computed merkle root of its
   transactions.
8. Its first transaction is a valid coinbase.
9. Every non-coinbase transaction is valid under the rules in
   sections 7.1 and 7.7 (including the anti-spam PoW at the
   declared priority).
10. No transaction appears more than once.
11. The coinbase outputs sum to at most
    `subsidy(height) + sum(transaction_fees)`.

---

## 9. Proof of Aiir

### 9.1 Motivation

Pure SHA-256d (Bitcoin's proof of work) is ASIC-friendly by design: the
function is simple, stateless, and perfectly parallelizable, which is
exactly what fixed-function silicon is best at. This leads to a few
large mining farms dominating the network, defeating the "anyone can
participate" goal (section 0).

**Proof of Aiir** is BitAiir's answer: it wraps `double_sha256` in a
memory-hard Argon2id step. Argon2id requires tens of megabytes of fast
random-access memory per invocation, with sequential dependencies that
cannot be efficiently parallelized across cores. This forces any
competitive miner to supply:

- A general-purpose CPU that can execute Argon2id efficiently, and
- Tens of megabytes of low-latency RAM per mining worker.

The economics of building an ASIC under those constraints are
dramatically worse than for pure SHA-256. A commodity CPU with DDR4 /
DDR5 memory remains competitive indefinitely.

`double_sha256` is still present at both ends of the computation, so
the hash primitives already implemented in `bitaiir-crypto` are fully
reused.

### 9.2 Algorithm

Given a serialized block header `header_bytes`, the Proof-of-Aiir hash
is computed as follows. The function is named `aiir_pow` in Rust code
to keep the identifier idiomatic; "Proof of Aiir" is the protocol
name used in documentation, UX, and marketing.

```
fn aiir_pow(header_bytes: &[u8]) -> Hash256 {
    // Step 1: a fast SHA-256 digest seeds the memory-hard step.
    let seed: [u8; 32] = sha256(header_bytes);

    // Step 2: Argon2id is the anti-ASIC barrier. The salt comes from
    // the header's prev_block_hash field so each chain tip produces a
    // fresh memory pattern; this prevents precomputing an Argon2
    // rainbow table.
    let salt: [u8; 16] = header_bytes.prev_block_hash[..16];

    let memory_work: [u8; 32] = argon2id(
        password = seed,
        salt = salt,
        memory_cost = 65_536,   // kibibytes, i.e. 64 MiB
        time_cost = 1,
        parallelism = 1,
        output_len = 32,
    );

    // Step 3: final identity is double_sha256 over header + memory_work.
    double_sha256(&[header_bytes, &memory_work[..]].concat())
}
```

The function is pure: the same `header_bytes` always yields the same
output. Verification and mining both run this identical function.

### 9.3 Difficulty target encoding (`bits`)

`bits` is a 4-byte compact encoding of a 256-bit target, using
Bitcoin's format:

- The high byte is the exponent `E`.
- The low three bytes are the mantissa `M`, interpreted as a 24-bit
  big-endian unsigned integer.
- The target is `M × 2^(8 × (E − 3))`.

A block is valid if and only if its `aiir_pow` hash, treated as a
256-bit unsigned integer, is less than or equal to the decoded target.

### 9.4 Difficulty adjustment

Every **20 blocks** (approximately 100 seconds at the target block
time), the network recomputes the target from the time it took to mine
the previous 20-block window:

```
actual_time   = block[i].timestamp - block[i - 20].timestamp
expected_time = 20 * 5             // 100 seconds

new_target = old_target * actual_time / expected_time
```

The ratio `actual_time / expected_time` is clamped to the range
`[1/4, 4]` to prevent a single window from changing the difficulty by
more than a factor of 4. The resulting `new_target` is re-encoded into
`bits` form with any necessary rounding, and becomes the required
target for the next 20 blocks.

A future protocol version may migrate to per-block difficulty
adjustment using LWMA (Linearly Weighted Moving Average), which
gives even faster response and smoother transitions. The 20-block
batch retarget is the v1 choice for implementation simplicity.

### 9.5 Initial difficulty

The genesis block and every block up to and including block 19 use
the hardcoded `bits = 0x2000ffff`. This target is deliberately easy so
that the first miners, running Proof of Aiir on commodity CPUs, can
produce blocks at roughly the target rate even without Argon2id
optimization. The first retarget happens at block 20.

### 9.6 Median time past

A block's `timestamp` must be strictly greater than the median of the
previous 11 blocks' timestamps. This prevents a miner from producing a
long chain of artificially-old blocks to manipulate difficulty.

### 9.7 Calibration of Argon2id parameters

The Argon2id parameters `(memory=64 MiB, time=1, parallelism=1)` were
chosen to balance three goals:

1. **ASIC hostility.** 64 MiB of low-latency memory per mining worker
   is expensive to replicate in custom silicon. Scaling the memory up
   further helps more but excludes low-RAM devices.
2. **CPU friendliness.** Modern laptops with 8 GiB of system RAM can
   sustain dozens of Argon2id invocations per second per core without
   swapping. Phones with 4 GiB+ can also run the function, though
   thermal and battery constraints limit sustained mining in practice
   (see section 19).
3. **Verification equality.** Because `time_cost = 1` and
   `parallelism = 1`, mining and verification perform the same amount
   of work per attempt. There is no cheaper shortcut for verifiers.

Any future change to these parameters is a hard fork.

### 9.8 Future work: replacement hash

If, despite the Argon2id wrap, ASIC advantage becomes problematic in
practice, the protocol may hard-fork to a different inner function
(for example RandomX, which is explicitly designed to saturate a
modern out-of-order CPU pipeline). Such a fork would be a community
decision and must publish its replacement function, target,
calibration, and activation height in this document.

---

## 10. Canonical encoding

All hashes (transaction IDs, block hashes, merkle inputs, anti-spam PoW
preimages) are computed over a canonical binary encoding of the
corresponding Rust struct.

**Version 1** uses `bincode` v2.x in its `config::standard()` mode via
the `serde` bridge. This is an implementation-defined choice that is
frozen into the protocol: any implementation that wants to match
BitAiir's consensus hashes must produce byte-for-byte identical bytes
for the same struct values.

The canonical encoding is defined operationally as "whatever
`bincode::serde::encode_to_vec(value, bincode::config::standard())`
produces for the Rust struct definitions given in this document".
Future protocol versions may switch to a hand-rolled wire format for
better auditability; such a change is a hard fork.

The canonical encoding is used **only** for content that is hashed
(transactions, headers) or persisted to local storage. The P2P wire
format (section 11) uses a hand-rolled byte layout per message type so
that framing stays stable even if canonical encoding changes.

---

## 11. P2P network

### 11.1 Framing

Every P2P message is a three-part frame:

```
| magic (4 bytes) | command (12-byte ASCII, NUL-padded) | length (u32 LE) | checksum (4 bytes) | payload |
```

- **magic** is the 4-byte network identifier from section 3.1.
  A receiver drops any message whose magic does not match the local
  active network.
- **command** is the ASCII name of the message type (see section 11.3),
  left-aligned and zero-padded to 12 bytes.
- **length** is the payload length in bytes, little-endian unsigned 32.
- **checksum** is the first 4 bytes of `double_sha256(payload)`.
- **payload** is the message-specific byte layout.

### 11.2 Protocol version

The network-layer protocol version is `1`. A `Version` message
exchanges the sender's protocol version, feature flags, timestamp,
user agent, and best block height; peers use the minimum of the two
reported versions to decide which wire format to use. Future versions
may add fields to existing messages or introduce new commands; a
receiver that does not recognize a command silently drops it.

### 11.3 Message types

The following commands are defined in v1. Payload layouts are
hand-rolled little-endian binary — no bincode — so the wire format is
auditable independently of the canonical encoding used for hashing.

| Command       | Direction | Purpose                                                                     |
| ------------- | --------- | --------------------------------------------------------------------------- |
| `version`     | both      | Opening handshake; announces version, services, timestamp, user agent, tip  |
| `verack`      | both      | Acknowledges a `version` message; empty payload                             |
| `ping`        | both      | Keepalive request, carries a random `u64` nonce                             |
| `pong`        | both      | Keepalive response, echoes the `ping` nonce                                 |
| `getheaders`  | both      | Header-sync request carrying a block locator (§11.5)                         |
| `headers`     | both      | Batch of block headers, capped at 2000 per message                          |
| `getblocks`   | both      | Request block bodies from a given height onward                             |
| `block`       | both      | A serialized block body (canonical bytes)                                   |
| `syncdone`    | both      | End-of-stream marker for a block sync                                       |
| `cmpctblock`  | both      | BIP 152-style compact block (§11.6)                                          |
| `getblocktxn` | both      | Request missing txs for a previously-received compact block                 |
| `blocktxn`    | both      | Reply to `getblocktxn`: the requested transactions in order                 |
| `tx`          | both      | A serialized transaction for mempool gossip                                 |
| `getaddr`     | both      | Request a peer's list of known addresses                                    |
| `addr`        | both      | Batch of known peer addresses (cap 1000 per message)                        |

### 11.4 Handshake

After TCP connect, both ends send `version`. On receiving a peer's
`version`, each end validates it (protocol version ≥ local minimum,
timestamp within 90 minutes) and responds with `verack`. The
connection is considered handshake-complete once each end has both
sent and received `verack`. Any message other than `version` / `verack`
before handshake completion causes immediate disconnection.

### 11.5 Header-first sync with block locator

Initial and delta sync both use a **block locator**: a list of block
hashes ordered newest-first, with exponentially increasing steps
between consecutive entries. The locator starts from the requester's
current tip, steps back by 1 for the first 10 entries, then doubles
the step size (2, 4, 8, 16 …) and always terminates with the genesis
block hash. The list is capped at 64 entries (`MAX_LOCATOR_ENTRIES`).

The receiver of a `getheaders(locator)` walks the locator from first
to last and responds with headers starting at the deepest common
ancestor it finds on its own main chain. One round trip locates the
fork point regardless of how deep the divergence is; this avoids the
"one block per round trip" stepping that naive chain sync would
require.

After the header chain is known, the requester walks forward block by
block, fetching bodies via `getblocks` / `block` until it reaches the
tip or sees a `syncdone`. Bodies are validated in order so a peer
sending a bad block gets disconnected before its bogus chain is
accepted.

### 11.6 Compact block relay

Newly-mined blocks are relayed in compact form (inspired by BIP 152).
The `cmpctblock` message carries the block header, a per-block random
`nonce_salt`, a vector of 6-byte short IDs — one per transaction —
and a (usually small) vector of pre-filled transactions for outputs
the sender expects the receiver not to have yet (at minimum, the
coinbase).

Receivers look up short IDs in their mempool. Any short IDs that do
not match a mempool transaction become a `getblocktxn` request
containing the missing indexes; the sender replies with `blocktxn`
carrying the missing transactions in the same order. The receiver
then reconstructs the full block and validates it.

The short ID is the first 6 bytes of `siphash24(key=nonce_salt, data=txid)`.
A fresh random `nonce_salt` per block prevents precomputed collisions
from poisoning mempools network-wide.

### 11.7 Transaction gossip

A node that accepts a new transaction into its mempool broadcasts a
`tx` message to every connected peer except the one it was received
from. Receivers validate the transaction (signatures, UTXO
availability, anti-spam PoW at the declared priority) before inserting
it into their own mempool and re-broadcasting. Transactions that fail
validation cost the sender rate-limit credit (see §11.9) but do not
by themselves cause disconnection.

### 11.8 Peer discovery (`getaddr` / `addr`)

Nodes maintain a local address database of known peers with their
last-seen timestamps. On connect, either end may send `getaddr` to
request the other's address list; the response is one or more `addr`
messages (capped at 1000 entries each) carrying `(ip:port, services,
timestamp)` tuples. Received addresses are merged into the local
database with the newer `timestamp` winning.

### 11.9 Rate limiting and bans

Each peer is throttled by a token bucket with **capacity 200** tokens
and a **refill rate of 100 tokens/second**. Every incoming P2P message
costs 1 token. A peer that drains the bucket to zero and attempts to
send more is immediately disconnected and banned.

**Ban duration** is exponential in the peer's repeat-offense count,
capped at 64× the base duration:

```
ban_duration = base_ban_secs × min(2^(offenses - 1), 64)
```

With the default `base_ban_secs = 600` (10 minutes), the cap is about
10 hours 40 minutes. Bans are stored in a `banned_ips` table in the
daemon's redb database and survive restart. A peer whose ban window
has expired may reconnect; a repeat offense within the window extends
the ban (still subject to the 64× cap).

The token bucket and base ban duration are defaults, not consensus
rules — operators may tune them via `[rate_limit]` in config. The
protocol requires only that a well-behaved peer be able to sustain
normal traffic indefinitely.

### 11.10 Seed / DNS-seed bootstrapping

A fresh node with no saved `known_peers` and no `--connect` address
consults two compiled-in fallbacks, in order:

1. **DNS seeds** — hostnames whose A/AAAA records resolve to healthy
   peers. Re-resolved once an hour.
2. **Hardcoded seed nodes** — a short list of long-lived static-IP
   nodes embedded in the binary.

Both lists are network-specific. The Rust constants live in
`crates/bitaiir-daemon/src/peer_manager.rs`:
`SEED_NODES_{MAINNET,TESTNET}`, `DNS_SEEDS_{MAINNET,TESTNET}`.

In the current pre-launch state all four arrays are empty — operators
wishing to bootstrap must use `--connect <ip:port>` until public
infrastructure is registered. DNS seeders follow the
[`bitcoin-seeder`](https://github.com/sipa/bitcoin-seeder) pattern:
crawl the network, rank by uptime, expose rotating A/AAAA records
under a known hostname, and register that hostname in the
`DNS_SEEDS_*` array before release.

### 11.11 Transport security

P2P connections in v1 are **plaintext TCP**. The payloads are
self-authenticating — blocks and transactions carry proofs of work and
signatures — so passive eavesdropping cannot inject fraudulent data,
only observe it. Active MITM is possible in principle but cannot
produce a valid block or transaction it did not compute itself, so at
worst an attacker can drop messages between the two honest peers.

TLS on the RPC interface is separate and opt-in (section 15.4). Adding
Noise / TLS to the P2P layer is explicitly deferred to a future
protocol version; the trade-off is code complexity and handshake cost
for a threat (traffic analysis) that is outside the payment-integrity
scope of v1.

---

## 12. Fork choice and reorganization

### 12.1 Most-cumulative-work rule

When a node learns about a block that does not build on its current
tip, it compares the cumulative proof-of-work of the two chains. The
chain with the **strictly greater cumulative work** is the new main
chain. Ties keep the current tip (first-seen wins).

Cumulative work is the sum, over every block from genesis to the tip,
of `2^256 / (target + 1)`. This is the same formula Bitcoin uses and
is stored alongside each block in the storage layer so fork choice is
O(1) rather than a per-comparison rescan.

### 12.2 Reorg execution

A reorg has three phases, all executed atomically:

1. **Disconnect** each block from the current tip back to the fork
   point, in reverse order. For each disconnected block, apply its
   **undo record** to the UTXO set: reinsert the outputs its
   transactions consumed, remove the outputs its transactions created.
2. **Apply** each block from the fork point forward along the new
   chain, in order. For each applied block, update the UTXO set and
   run full validation (section 8.4). Any invalid block aborts the
   reorg and restores the previous chain from the in-memory snapshot
   taken at the start of the operation.
3. **Persist** the new chain state to disk in a single atomic redb
   write transaction. If the write fails, the in-memory state is
   rolled back and the on-disk state is unchanged.

In-memory rollback uses a snapshot captured at the start of the reorg
so that any failure — invalid block, disk error, panic — leaves the
node with exactly the pre-reorg state. Callers see one atomic
`AcceptOutcome` enum (`OnTip`, `Reorg`, `Orphan`, `Rejected`) and do
not have to reason about partial application.

### 12.3 Undo records

Every applied block produces an **undo record** that captures the
inputs the block consumed. A reorg disconnecting the block applies
the record to reinsert those UTXOs; a reorg applying a new block
writes a fresh undo record so the operation can itself be undone
later. Undo records are stored in a dedicated redb table keyed by
block hash.

### 12.4 Reorg depth

The protocol does not impose a maximum reorg depth. In practice a
deep reorg is extraordinarily unlikely because each block's Argon2id
cost makes rewriting chain history disproportionately expensive.
Wallets and merchants are free to apply local confirmation thresholds
before treating a payment as final; the reference wallet treats
1 confirmation as sufficient for everyday-payment UX (section 0) and
6 confirmations as settlement.

---

## 13. Mempool

### 13.1 Policy — not consensus

The mempool is a local policy decision, not a consensus rule. Two
honest nodes may have arbitrarily different mempools and still agree
on the main chain. Everything in this section describes the reference
implementation's behavior; alternative implementations are free to
deviate as long as they produce valid blocks and relay valid
transactions.

### 13.2 Acceptance rules

A transaction is accepted into the reference mempool if and only if:

1. It parses as a valid `Transaction` under the canonical encoding.
2. It passes every check in section 7.1 against the node's current
   UTXO set (including section 7.7 anti-spam PoW at the declared
   priority).
3. None of its inputs collide with an already-mempool-reserved UTXO.
4. Its serialized size plus the current mempool size does not exceed
   the configured `max_bytes` (default 50 MB). If it would exceed the
   cap, see §13.4 (eviction).

### 13.3 Ordering

Entries are ordered by `(Reverse(pow_priority), arrival_seq)`:

- Higher declared priority first.
- On ties, older arrival first.

Priority is a sender-declared `u64` validated by anti-spam PoW
(section 7.7), so ordering is deterministic across nodes that have
seen the same transactions in the same order, and a high-priority
entry cannot jump the queue without paying proportionally more CPU.

### 13.4 Eviction

When an incoming transaction would push the mempool over `max_bytes`,
the mempool evicts entries from the **tail of the ordering** —
lowest priority, newest arrival — until the new transaction fits. The
incoming transaction itself is rejected if it cannot fit even after
evicting everything strictly lower-ordered than it, which prevents a
flood of low-priority transactions from displacing high-priority ones.

### 13.5 Block assembly

A miner selects transactions in order from the front of the mempool,
respecting the block size cap and skipping any transaction whose
inputs collide with a transaction already selected for the same
block. This gives senders a deterministic preview of their confirmation
latency: at priority `N`, a transaction reaches the front of the
queue ahead of every priority-`< N` entry currently in the mempool.

### 13.6 Pending spends

Because `/sendtoaddress` is fire-and-forget (the RPC returns as soon
as the wallet has selected and signed inputs, and the tx-PoW is mined
in a background task), the wallet tracks a short-lived `pending_spends`
set of `(txid, vout)` tuples reserved by in-flight sends. The mempool
acceptance check (§13.2 item 3) consults this set in addition to the
mempool's own spent-tracking so concurrent sends on the same wallet
do not double-select the same UTXO.

---

## 14. Wallet

### 14.1 HD derivation (BIP32 / BIP39 / BIP44)

The reference wallet is **hierarchical deterministic**:

- A **24-word BIP39 mnemonic** is generated (256 bits of entropy) and
  stored encrypted on disk (§14.3).
- A BIP32 root seed is derived from the mnemonic + empty passphrase.
- Per-address keys are derived at the BIP44 path
  `m/44'/8888'/0'/0/<index>`, where `8888'` is BitAiir's unregistered
  placeholder coin type.
- A wallet restore from mnemonic rebuilds every address deterministically;
  the node rescans the chain for outputs paying any of the rederived
  `hash160(pubkey)` values.

The coin type `8888` is a provisional value that will be replaced by a
SLIP-0044 registration once the protocol is stable enough to apply.
Any change is a wallet-compatibility break, not a consensus break.

### 14.2 RPC surface

The wallet exposes `getmnemonic` and `importmnemonic` RPCs for explicit
backup / restore, and `getnewaddress` / `listaddresses` /
`getbalance <addr>` / `sendtoaddress <addr> <amt>` for normal operation.
`/sendtoaddress` returns the txid as soon as inputs are selected and
signed; the tx-PoW is mined in a background task (see §13.6 for the
concurrency implications).

### 14.3 At-rest encryption

The wallet state (mnemonic, derived keys, imported WIFs) is encrypted
with **AES-256-GCM**. The encryption key is derived from the operator's
passphrase via **Argon2id** at the same `(memory=64 MiB, time=1,
parallelism=1)` parameters used for Proof of Aiir — the parameters are
already present in the binary and match the cost model the project
targets. The derived key is held only in memory while the wallet is
unlocked and is zeroized on drop.

An unencrypted wallet (no passphrase set) is allowed for development
and test networks; the reference implementation warns loudly on
mainnet startup when the wallet is unencrypted.

---

## 15. RPC interface

### 15.1 Transport

The RPC server speaks **JSON-RPC 2.0** over HTTP (or HTTPS, §15.4).
Methods accept positional or named parameters. The reference daemon
listens on `127.0.0.1:<default_rpc_port>` by default; binding to a
non-loopback interface requires an explicit `--rpc-addr` flag and
triggers a security warning at startup.

### 15.2 Cookie authentication

On startup the daemon writes a random credential to
`<data_dir>/.cookie` as a single line:

```
__cookie__:<base64 random bytes>
```

The cookie is regenerated on every startup and deleted on clean
shutdown. The file is chmod `0600` on Unix. Clients (including the
bundled `bitaiir-cli` and the TUI) read the file and forward the
whole line as an HTTP Basic credential
(`Authorization: Basic base64(user:password)`).

### 15.3 Config-based authentication

For environments where clients cannot read a local file — LAN exposure
behind a proxy, a remote operator — the cookie file is skipped and the
daemon uses the explicit `[rpc] user` and `[rpc] password` from
`bitaiir.toml` instead. Every request still authenticates with HTTP
Basic; only the credential source changes.

The `[rpc] allow_ip = ["…"]` option adds a TCP-level IP allowlist
applied **before** authentication. Requests from disallowed IPs are
dropped without the server ever reading the body.

### 15.4 Transport security (TLS)

TLS is **opt-in** via `[rpc] tls = true`. When enabled:

- If `[rpc] tls_cert_path` and `tls_key_path` are not set, the daemon
  generates a self-signed ECDSA P-256 certificate with a 10-year
  validity and SANs `localhost`, `127.0.0.1`, `::1`, writes the pair
  to `<data_dir>/rpc.cert` and `<data_dir>/rpc.key` (chmod 0600), and
  reuses it on subsequent starts.
- If the two paths are set, the daemon loads the operator-provided
  certificate and key. This is the path for operators who want a
  CA-signed cert on a public hostname.

The RPC stack is `rustls` (ring provider) + `tokio-rustls` + `rcgen`,
chosen to keep the RISC-V cross-build green.

`bitaiir-cli` automatically trusts the local self-signed cert at
`<data_dir>/rpc.cert` when the daemon is on the same host. For
other deployments it accepts `--rpc-cafile` (a CA bundle) or
`--insecure` (skip verification, for development only).

### 15.5 Method surface

The RPC surface is not part of the consensus protocol — individual
implementations may add or drop methods at will. The reference
implementation exposes, at minimum:

- Chain: `getblockchaininfo`, `getblock <height>`
- Mempool: `getmempoolinfo`
- Wallet: `getnewaddress`, `getbalance <addr>`, `listaddresses`,
  `sendtoaddress <addr> <amt>`, `getmnemonic`, `importmnemonic`
- Mining: `mine-start`, `mine-stop`
- Peers: `addpeer <ip:port>`, `listpeers`
- Lifecycle: `stop`

See the `README.md` command table for the full list.

---

## 16. Genesis block

### 16.1 Determinism

Each network's genesis block is **deterministically computable**:
every node running the same codebase on the same network computes the
same genesis block from the same hardcoded inputs and accepts it
without any external data. The inputs are:

- A fixed UTC timestamp (§3.1).
- A fixed coinbase message (§3.1).
- A provably-unspendable "burn" recipient address derived from
  `hash160(network.genesis_burn_phrase)`. The 100 AIIR genesis subsidy
  is paid to this address and is permanently unspendable, since no
  one holds a private key whose public key hashes to that 20-byte
  value.
- A linear nonce search from `0` upward against
  `bits = 0x2000ffff` (§9.5).

Because all inputs are fixed and the search is purely `aiir_pow` at
the initial target, two nodes that have never communicated arrive at
the identical genesis header hash. The first coinbase is thus on both
nodes' disks from their first tick without any bootstrap data.

### 16.2 Mainnet

- **Coinbase message:** `"Poder360 29/03/2026 Master deixa rombo de R$ 52 bi no FGC e de R$ 2 bi em fundos"`
- **Timestamp:** 2026-03-29 00:00:00 UTC (Unix `1743206400`).
- **Burn phrase:** `"BitAiir Genesis Burn"`.
- **bits:** `0x2000ffff`.
- **Nonce:** found by deterministic search (first `u32` such that
  `aiir_pow(header)` meets `bits`).

### 16.3 Testnet

- **Coinbase message:** `"BitAiir Testnet Genesis"`.
- **Timestamp:** 2026-04-06 00:00:00 UTC (Unix `1743897600`).
- **Burn phrase:** `"BitAiir Testnet Genesis Burn"`.
- **bits:** `0x2000ffff`.
- **Nonce:** found by deterministic search, as on mainnet.

The different timestamp, message, and burn phrase guarantee that the
two networks' genesis hashes are disjoint even on an adversarial
deployment that tried to share data directories.

---

## 17. Open questions

The following items are explicitly not decided and must be revisited
before mainnet:

1. **Precise tx-level PoW target.** The provisional value in section
   7.7 needs to be calibrated against real hardware so that a median
   commodity laptop finds a priority-1 nonce in approximately 2 seconds.
2. **Initial Proof-of-Aiir difficulty.** The `bits = 0x2000ffff`
   initial value must be validated against real CPU performance so
   that the first 20 blocks take roughly `20 * 5 = 100 seconds` on a
   single-laptop bootstrap network.
3. **Public seed / DNS-seed infrastructure.** The per-network arrays
   in `peer_manager.rs` are currently empty; before v0.1.0 mainnet,
   at least two independently operated seed nodes and one DNS seeder
   per network must be registered.
4. **BIP44 coin type.** `8888` is an unregistered placeholder; a
   SLIP-0044 registration is needed before long-term wallet format
   stability is promised.
5. **Replacement PoW** (section 9.8). If Argon2id is eventually
   circumvented, what replaces it and how is the fork activated?
6. **Alias registry + escrow primitive.** Spec'd separately in a
   forthcoming update to this document; both are targeted at commerce
   UX and ship before v0.1.0 mainnet.

---

## 18. Mining command-line experience

The reference daemon `bitaiird` and the CLI client `bitaiir-cli` must
expose mining as a first-class, single-command feature. A user who has
installed BitAiir should be able to start mining with no extra
configuration beyond choosing how many CPU threads to dedicate.

### 18.1 Required commands

`bitaiir-cli mine` (or an equivalent subcommand) must support at minimum:

- `--threads <N>`: number of worker threads to use. Default: one less
  than the number of available logical cores, so the machine remains
  responsive.
- `--address <addr>`: the BitAiir address to receive mined block
  rewards. Default: a newly generated address stored in the wallet.
- `--stop-after <N>`: optional cap on blocks mined, for testing.

The command must print a human-readable, live-updating status that
shows at least the current best block height, local hashrate, elapsed
time, and a running total of blocks found by this miner.

### 18.2 Embedded mining in the daemon

`bitaiird` must accept a `mine=1` option in `bitaiir.conf` (or an
equivalent CLI flag) that enables mining as part of the running node,
without a separate process. This makes "I run a node, I mine" the
default deployment, matching Bitcoin's `bitcoind -gen` behavior from
its earliest days.

### 18.3 Rationale

BitAiir's design goal of "anyone who can run the daemon can mine"
(section 0) is only real if mining is trivially accessible. If the
only way to mine is to install and configure a separate third-party
miner, the goal is effectively unmet. Bundling mining into the
reference implementation is the practical way to preserve the
"open participation" invariant as the project grows.

Mining is not mandatory — running a non-mining node must remain the
default — but it must be **available with one command**.

---

## 19. Mobile participation

### 19.1 Status

The protocol does not block mining on mobile devices. The 64 MiB
Argon2id memory cost fits comfortably within the per-app memory budget
of any phone with 4 GiB+ of system RAM, which covers essentially every
Android or iOS device sold in the last several years. Modern mobile
CPUs (Apple Silicon, Snapdragon 8 Gen 3, MediaTek Dimensity 9000+)
execute Argon2id at a hashrate comparable to mid-range laptops.

### 19.2 Ecosystem constraints

While the *protocol* permits mobile mining, the *ecosystem* around
mobile devices makes it impractical as a primary use case:

1. **App store policies.** Both Apple's App Store Review Guideline
   3.1.5(b) and Google Play's Developer Policy explicitly forbid
   on-device cryptocurrency mining applications. Any BitAiir mobile
   miner must be distributed outside these stores:
   - **Android:** via F-Droid (which allows mining apps), direct APK
     download, or alternative stores such as Aurora.
   - **iOS:** no general-purpose distribution path exists. The iOS
     ecosystem cannot host a BitAiir miner.
2. **Thermal throttling.** Sustained full-CPU mining triggers OS-level
   thermal protection within seconds to minutes, reducing hashrate by
   50 % or more. Mobile mining is effectively limited to short bursts
   or to use while the device is actively cooled (plugged in, face-up,
   not in a pocket).
3. **Battery drain.** Mining at full CPU for one hour consumes roughly
   20–40 % of a typical phone's battery. Users will not run sustained
   mining on a daily-driver device.

### 19.3 The intended mobile posture

For version 1, mobile devices are the **payment platform** for
BitAiir, not the **mining platform**. The reference mobile wallet (when
it exists) will:

- Be a **light client**: it downloads and verifies block headers, uses
  Merkle proofs to check balances, and does not store the full chain.
- Support the core payment UX: receive a payment via QR code, send a
  payment via address or QR scan, show balance and transaction
  history.
- Include an **optional mining toggle**, active only when the device
  is plugged in, idle, on Wi-Fi, and above a battery threshold — and
  **only** on platforms where distribution is legal (i.e. sideloaded
  Android). On iOS, mining is not offered at all.

### 19.4 Progressive Web App as a future distribution option

A Progressive Web App (PWA) running in a mobile browser can host a
WebAssembly build of the Proof-of-Aiir miner. This path:

- Is not subject to app-store policies (it is a website).
- Works on both Android and iOS browsers.
- Runs Argon2id at roughly 2–5× the cost of native code (acceptable
  for light participation).
- Is subject to browser-level tab-throttling, which limits background
  mining.

The PWA approach is out of scope for version 1 of the reference
implementation but is noted here as a potential cross-platform path
for future work.

### 19.5 Summary

| Platform               | Wallet | Mining                  |
| ---------------------- | ------ | ----------------------- |
| Desktop (Linux/Win/Mac)| Yes    | Yes, first-class        |
| Android (F-Droid/APK)  | Yes    | Yes, opt-in             |
| Android (Play Store)   | Yes    | No (policy blocks it)   |
| iOS (App Store)        | Yes    | No (policy blocks it)   |
| Browser / PWA          | Future | Future, experimental    |

Mobile is a first-class payments platform and a best-effort mining
platform. The design does not exclude phones — it recognizes where the
ecosystem stops the protocol from reaching them.

---

## 20. Change log

| Date       | Version | Change                                                            |
| ---------- | ------- | ----------------------------------------------------------------- |
| 2026-04-09 | draft   | Initial draft. Sections 1–12.                                     |
| 2026-04-09 | draft   | Redesign: payment-first goals, tail emission, Proof of Aiir, zero fees with tx-level PoW, 5 s blocks. |
| 2026-04-09 | draft   | Branding: rename the PoW function from "AIIRPoW" to "Proof of Aiir" in the docs; the Rust identifier remains `aiir_pow`. |
| 2026-04-21 | draft   | Add testnet parameters (magic, ports, data dir, coinbase maturity, genesis) as first-class in section 3; document both networks' genesis inputs. |
| 2026-04-21 | draft   | Add `pow_priority` field on `Transaction`: sender-declared mempool priority enforced by stricter tx-PoW target (`min_target / priority`); mempool orders by priority descending with arrival tiebreak. |
| 2026-04-21 | draft   | Expand section 11 (P2P network): message type table, handshake, header-first sync with block locator, BIP 152-style compact blocks, rate limit (token bucket + exponential ban), seed / DNS-seed bootstrap. |
| 2026-04-21 | draft   | Add section 12 (fork choice and reorg): most-cumulative-work rule, disconnect/apply/persist phases, undo records, atomic in-memory snapshot + on-disk redb transaction. |
| 2026-04-21 | draft   | Add section 13 (mempool): size-capped (default 50 MB), priority ordering, eviction policy, pending-spends for concurrent-send UTXO safety. |
| 2026-04-21 | draft   | Add section 14 (wallet): HD BIP32/39/44 at path `m/44'/8888'/0'/0/<index>`, AES-256-GCM + Argon2id at rest. |
| 2026-04-21 | draft   | Add section 15 (RPC interface): cookie auth, config-based auth + IP allowlist, opt-in TLS with self-signed or operator-provided cert. |
| 2026-04-21 | draft   | Reduce open-questions list: DNS seeds have code structure, P2P plaintext decided for v1, genesis determinism resolves the earlier "genesis contents" open question. |
