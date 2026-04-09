# BitAiir Protocol Specification

**Version:** 1
**Status:** Draft — subject to change until the genesis block is mined and published.
**Last updated:** 2026-04-09

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
   hostile to ASIC and GPU acceleration (see section 8) so that a
   commodity CPU remains competitive throughout the project's lifetime.
4. **Decentralized issuance, forever.** There is no pre-mine, no
   foundation allocation, no ICO. New coins enter circulation only via
   the coinbase transaction of each mined block. Issuance does not stop
   — there is a fixed tail emission so that mining always pays (see
   section 3.2).
5. **Anti-spam without fees.** Because fees are zero, transactions
   themselves include a small proof of work that costs the sender
   roughly two seconds of CPU time (section 6.7). This makes flood
   attacks uneconomical without charging honest users money.
6. **Mobile users can pay; desktop users mine.** The protocol does not
   block mobile mining, but the ecosystem realities (app-store policies,
   thermal throttling, battery drain) mean mobile is a first-class
   platform for wallets and a second-class platform for miners. See
   section 15 for the rationale.
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
  (section 8). In code the corresponding function is written
  `aiir_pow()` for Rust-identifier friendliness.
- New coins are issued via the coinbase transaction of each block,
  following a halving schedule that bottoms out at a permanent tail
  emission (section 3).
- Transactions carry a small embedded proof of work as a spam
  mitigation, replacing the fee-based anti-spam of Bitcoin
  (section 6.7).

All cryptographic primitives, address formats, and signed-message rules
are shared with Bitcoin's lineage, with BitAiir-specific identifiers so
a BitAiir artifact cannot be confused with a Bitcoin artifact.

---

## 2. Constants table

| Name                           | Value                                        | Status       |
| ------------------------------ | -------------------------------------------- | ------------ |
| Protocol version               | 1                                            | decided      |
| Network magic bytes            | `0xB1 0x7A 0x11 0xED`                        | provisional  |
| Default P2P port               | 8444                                         | provisional  |
| Default RPC port               | 8443                                         | provisional  |
| Address prefix (string)        | `"aiir"`                                     | decided      |
| Address version byte           | `0x00`                                       | decided      |
| WIF version byte               | `0xfe`                                       | decided      |
| Signed message prefix          | `"BitAiir Signed Message:\n"`                | decided      |
| Atomic units per whole AIIR    | 100_000_000 (10^8)                           | decided      |
| Initial block reward           | 100 AIIR                                     | provisional  |
| Blocks per halving             | 50_000_000                                   | provisional  |
| Tail emission floor            | 10 AIIR / block                              | provisional  |
| Approximate long-term supply   | ~11.26 billion AIIR at year 100              | provisional  |
| Target block time              | 5 seconds                                    | provisional  |
| Difficulty retarget interval   | 144 blocks                                   | provisional  |
| Max difficulty adjustment      | 4× per retarget                              | provisional  |
| Initial difficulty `bits`      | `0x2000ffff`                                 | provisional  |
| Proof of work                  | Proof of Aiir (SHA-256d + Argon2id wrap)     | provisional  |
| Argon2id memory cost           | 65_536 KiB (64 MiB)                          | provisional  |
| Argon2id time cost             | 1 iteration                                  | provisional  |
| Argon2id parallelism           | 1 lane                                       | provisional  |
| Argon2id output length         | 32 bytes                                     | provisional  |
| Tx-level anti-spam PoW target  | ~2 s CPU time on commodity laptop            | provisional  |
| Max serialized block size      | 1_000_000 bytes                              | provisional  |
| Max serialized transaction size| 100_000 bytes                                | provisional  |
| Coinbase maturity              | 100 blocks                                   | provisional  |
| Locktime semantics             | block height only (no timestamp mode)        | provisional  |
| Time-past-median window        | 11 blocks                                    | provisional  |

---

## 3. Tokenomics

### 3.1 Atomic units

BitAiir uses 8 decimal places of precision. The smallest representable
quantity is one hundred-millionth of an AIIR:

```
1 AIIR = 100_000_000 atomic units
```

All on-chain amounts are stored and transmitted as `u64` counts of
atomic units. This follows Bitcoin's satoshi convention and matches the
`Amount` newtype in `bitaiir-types`.

### 3.2 Supply schedule — halvings plus tail emission

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
| 4   | 150,000,000 .. 200,000,000 | 12 AIIR (rounded down from 12.5) | 23.8 – 31.7 |
| 5+  | 200,000,000 .. ∞           | **10 AIIR (floor)** | 31.7+     |

From block `200,000,000` onward, the subsidy is exactly 10 AIIR per
block for the rest of the chain's existence.

**Total supply at key milestones** (rounded):

- End of Era 1: ~5.0 B AIIR mined
- End of Era 2: ~7.5 B AIIR mined
- End of Era 3: ~8.75 B AIIR mined
- End of Era 4: ~9.35 B AIIR mined
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

### 3.3 Rationale for tail emission

BitAiir is a payment currency, not a store of value. Continuous modest
emission:

- Guarantees miners always have a subsidy, even after fee-less block
  space stops rewarding them through fees (because there are no fees
  in BitAiir — see section 6.6).
- Encourages spending over hoarding, which is the correct incentive
  for a medium of exchange.
- Matches real-world fiat behavior (central banks target 2–3 %
  inflation); 0.5 % is well below that and nearly imperceptible in
  daily use.
- Removes the "fee-market cliff" that Bitcoin will face post-2140.

### 3.4 Rounding

Subsidy division is performed in **atomic units**, with integer
truncation. When era 4 would pay 12.5 AIIR, the actual payout is
`12_50_000_000 atomic units` rounded down to `12_50_000_000` which is
still representable; only half-AIIR boundaries require rounding (down).
This keeps arithmetic exact in `u64`.

The tail-emission floor of 10 AIIR is chosen to be a round number
rather than the exact geometric value, to keep the schedule easy to
reason about for users.

---

## 4. Addresses

### 4.1 Format

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

### 4.2 WIF (Wallet Import Format)

Private keys exported as WIF use the version byte `0xfe` (distinct from
Bitcoin mainnet `0x80` and testnet `0xef`), followed by the 32-byte
private key, followed by an optional compression flag `0x01`, all
passed through Base58Check:

```
wif_uncompressed = base58check(0xfe || privkey)
wif_compressed   = base58check(0xfe || privkey || 0x01)
```

---

## 5. Signed messages

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

## 6. Transactions

### 6.1 Model

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
- The transaction's embedded `pow_nonce` satisfies the anti-spam proof
  of work (section 6.7).

Transactions may have a fee of **zero** atomic units. Fees are
explicitly optional (section 6.6).

### 6.2 Structure

A transaction is the following Rust struct, serialized with the
canonical encoding defined in section 9:

```rust
struct Transaction {
    version: u32,
    inputs: Vec<TxIn>,
    outputs: Vec<TxOut>,
    locktime: u32,
    pow_nonce: u64,         // anti-spam PoW, see section 6.7
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

### 6.3 Txid

A transaction's ID is the `double_sha256` of its canonical serialization,
including signatures and `pow_nonce`. Re-signing the same transaction
under a different nonce would change its txid; this is prevented because
BitAiir requires RFC 6979 deterministic signatures, which are a pure
function of the private key and the sighash.

### 6.4 Sighash

The digest signed by a `TxIn` is computed by:

1. Cloning the transaction.
2. Clearing the `signature` field of every input to an empty `Vec<u8>`.
3. Clearing the `pow_nonce` field to `0`.
4. Leaving the `pubkey` field of every input intact.
5. Serializing the result with the canonical encoding.
6. Hashing with `double_sha256`.

Clearing `pow_nonce` in the sighash is important: otherwise the sender
would have to re-sign after mining the anti-spam PoW, creating a
chicken-and-egg problem.

This is the simplest possible sighash scheme. It signs all inputs and
all outputs (equivalent to Bitcoin's `SIGHASH_ALL`) and does not support
any other sighash flags.

### 6.5 Coinbase

The first transaction in every block must be a coinbase. It has:

- Exactly one input with `prev_out = (Hash256::ZERO, u32::MAX)`.
- The `signature` field of that input is free-form and is used by
  miners as an extra-nonce / tagging area.
- The `pubkey` field of that input is empty.
- `pow_nonce` is `0` (coinbase transactions are exempt from the
  anti-spam PoW; they are already bounded by the block's own PoW).
- Arbitrarily many outputs.
- `sum(outputs) ≤ subsidy(block_height) + sum(fees_in_block)`.

Where `fees_in_block` is the sum of all voluntary fees in non-coinbase
transactions included in the block.

Outputs created by a coinbase transaction mature after
**100 blocks**. A transaction that spends an immature coinbase output
is rejected.

### 6.6 Fees

The protocol imposes **no minimum fee**. A transaction is valid even
when `sum(input_amounts) == sum(output_amounts)`, i.e. when the
sender keeps no change for the miner.

A sender may voluntarily include a fee by making the output total less
than the input total. The difference is claimed by the block's coinbase
transaction. Miners are free to prioritize higher-fee transactions when
selecting from the mempool, but are not required to — the mempool
ordering policy is a local choice, not a consensus rule.

Because the block subsidy never falls below 10 AIIR (tail emission),
mining is always profitable even when every transaction in the block
has zero fee.

### 6.7 Anti-spam proof of work

Every non-coinbase transaction must carry a proof of work over its own
contents to prevent flood attacks. The sender computes this PoW once,
at send time, before broadcasting the transaction.

**Computation:**

```
fn compute_tx_pow(tx: &mut Transaction) {
    let tx_digest = {
        // Hash the transaction with pow_nonce temporarily set to zero.
        let mut canonical = tx.clone();
        canonical.pow_nonce = 0;
        double_sha256(canonical_encode(&canonical))
    };

    for nonce in 0u64.. {
        let attempt = double_sha256(&[&tx_digest[..], &nonce.to_le_bytes()].concat());
        if meets_tx_pow_target(&attempt) {
            tx.pow_nonce = nonce;
            return;
        }
    }
}
```

**Target:** the tx-level PoW target is chosen so that a commodity
laptop CPU finds a valid `pow_nonce` in approximately **2 seconds**.
The exact numerical target is part of the protocol and is calibrated
before mainnet. A provisional value is
`0x0000_000f_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff`,
meaning the first four bytes of the digest must be zero. This will be
tuned against real hardware benchmarks before mainnet.

**Verification** is a single `double_sha256` call, trivially cheap for
nodes and miners.

**Security property:** a spammer who wants to submit `N` transactions
per second must spend `2 * N` CPU-seconds of work per second. A
single-core attacker is capped at ~0.5 tx/s. Breaking 1000 tx/s
requires 2000 cores running continuously, which is economically
unattractive for spam purposes.

**Coinbase exemption:** coinbase transactions carry `pow_nonce = 0`.
They are not spam vectors because block production is already
rate-limited by the main (Proof of Aiir) proof of work.

---

## 7. Blocks

### 7.1 Structure

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

### 7.2 Block hash

The block hash is `aiir_pow(canonical_encode(BlockHeader))`, where
`aiir_pow` is the Rust name of the Proof-of-Aiir function defined in
section 8. A block is valid only if its hash, interpreted as a 256-bit
little-endian integer, is less than or equal to the target encoded by
`bits`.

The block hash is used both as the block's identity (the value stored
in the next block's `prev_block_hash`) and as the proof-of-work check
— just as in Bitcoin.

### 7.3 Merkle root

The `merkle_root` field must equal `merkle_root(tx_ids)` where `tx_ids`
is the ordered list of transaction IDs in the block, and `merkle_root`
is the Bitcoin-style pairwise `double_sha256` reduction. If a level has
an odd number of hashes, the last one is duplicated.

This inherits CVE-2012-2459 by construction. The mitigation is the
consensus rule **"a valid block must not contain duplicate
transactions"**, enforced by `bitaiir-chain` at validation time.

### 7.4 Validation rules

A block is valid if and only if all of the following hold:

1. Its serialized size is at most `MAX_BLOCK_SIZE` bytes.
2. Its header hash `aiir_pow(header_bytes)` is numerically ≤ the target
   encoded by `bits`.
3. Its `bits` field equals the value expected from the difficulty
   adjustment algorithm (section 8.4).
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
   sections 6.1 and 6.7 (including the anti-spam PoW).
10. No transaction appears more than once.
11. The coinbase outputs sum to at most
    `subsidy(height) + sum(transaction_fees)`.

---

## 8. Proof of Aiir

### 8.1 Motivation

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

### 8.2 Algorithm

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

### 8.3 Difficulty target encoding (`bits`)

`bits` is a 4-byte compact encoding of a 256-bit target, using
Bitcoin's format:

- The high byte is the exponent `E`.
- The low three bytes are the mantissa `M`, interpreted as a 24-bit
  big-endian unsigned integer.
- The target is `M × 2^(8 × (E − 3))`.

A block is valid if and only if its `aiir_pow` hash, treated as a
256-bit unsigned integer, is less than or equal to the decoded target.

### 8.4 Difficulty adjustment

Every **144 blocks** (approximately 12 minutes at the target block
time), the network recomputes the target from the time it took to mine
the previous 144-block window:

```
actual_time   = block[i].timestamp - block[i - 144].timestamp
expected_time = 144 * 5            // 720 seconds

new_target = old_target * actual_time / expected_time
```

The ratio `actual_time / expected_time` is clamped to the range
`[1/4, 4]` to prevent a single window from changing the difficulty by
more than a factor of 4. The resulting `new_target` is re-encoded into
`bits` form with any necessary rounding, and becomes the required
target for the next 144 blocks.

### 8.5 Initial difficulty

The genesis block and every block up to and including block 143 use
the hardcoded `bits = 0x2000ffff`. This target is deliberately easy so
that the first miners, running Proof of Aiir on commodity CPUs, can
produce blocks at roughly the target rate even without Argon2id
optimization. The first retarget happens at block 144.

### 8.6 Median time past

A block's `timestamp` must be strictly greater than the median of the
previous 11 blocks' timestamps. This prevents a miner from producing a
long chain of artificially-old blocks to manipulate difficulty.

### 8.7 Calibration of Argon2id parameters

The Argon2id parameters `(memory=64 MiB, time=1, parallelism=1)` were
chosen to balance three goals:

1. **ASIC hostility.** 64 MiB of low-latency memory per mining worker
   is expensive to replicate in custom silicon. Scaling the memory up
   further helps more but excludes low-RAM devices.
2. **CPU friendliness.** Modern laptops with 8 GiB of system RAM can
   sustain dozens of Argon2id invocations per second per core without
   swapping. Phones with 4 GiB+ can also run the function, though
   thermal and battery constraints limit sustained mining in practice
   (see section 15).
3. **Verification equality.** Because `time_cost = 1` and
   `parallelism = 1`, mining and verification perform the same amount
   of work per attempt. There is no cheaper shortcut for verifiers.

Any future change to these parameters is a hard fork.

### 8.8 Future work: replacement hash

If, despite the Argon2id wrap, ASIC advantage becomes problematic in
practice, the protocol may hard-fork to a different inner function
(for example RandomX, which is explicitly designed to saturate a
modern out-of-order CPU pipeline). Such a fork would be a community
decision and must publish its replacement function, target,
calibration, and activation height in this document.

---

## 9. Canonical encoding

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

---

## 10. Network

### 10.1 Magic bytes

Every P2P message is framed with a 4-byte network magic at its start:

```
0xB1 0x7A 0x11 0xED
```

Nodes drop any incoming bytes that do not start with this sequence.
This prevents accidental cross-talk between BitAiir and other protocols
that happen to share a TCP port.

### 10.2 Protocol version

The network-layer protocol version is `1`. When a new field is added to
any P2P message, the version number is bumped and nodes use the
minimum of the two peers' version numbers to decide which wire format
to use.

### 10.3 Ports

- Default P2P port: **8444**
- Default RPC port: **8443**

These are the ports the reference implementation listens on unless the
operator overrides them. They are not consensus rules.

---

## 11. Genesis block

**Status:** open

The genesis block will be mined and its full bytes added to this
document before the first mainnet release. Until then,
`bitaiir-chain` should produce a fresh, in-memory test genesis on every
startup for development purposes.

The genesis block's properties, once decided, will be:

- `version = 1`
- `prev_block_hash = Hash256::ZERO`
- `timestamp = <chosen at mining time>`
- `bits = 0x2000ffff`
- `nonce = <found at mining time>`
- Coinbase payload: an ASCII string identifying the BitAiir project
  and the date, analogous to Bitcoin's "The Times 03/Jan/2009
  Chancellor on brink of second bailout for banks".

---

## 12. Open questions

The following items are explicitly not decided and must be revisited
before mainnet:

1. **Genesis block contents** (section 11). Needs a coinbase payload,
   a timestamp, and a mined nonce.
2. **Precise tx-level PoW target.** The provisional value in section
   6.7 needs to be calibrated against real hardware so that a median
   commodity laptop finds a nonce in approximately 2 seconds.
3. **Initial Proof-of-Aiir difficulty.** The `bits = 0x2000ffff`
   initial value must be validated against real CPU performance so
   that the first 144 blocks take roughly `144 * 5 = 720 seconds` on a
   single-laptop bootstrap network.
4. **DNS seeds.** Where do fresh nodes get their first peers from? A
   hardcoded list? A DNS-based discovery scheme?
5. **P2P authentication.** Does BitAiir v1 encrypt peer connections,
   or is it cleartext like Bitcoin's original protocol?
6. **Replacement PoW** (section 8.8). If Argon2id is eventually
   circumvented, what replaces it and how is the fork activated?

---

## 13. Change log

| Date       | Version | Change                                                            |
| ---------- | ------- | ----------------------------------------------------------------- |
| 2026-04-09 | draft   | Initial draft. Sections 1–12.                                     |
| 2026-04-09 | draft   | Redesign: payment-first goals, tail emission, Proof of Aiir, zero fees with tx-level PoW, 5 s blocks. |
| 2026-04-09 | draft   | Branding: rename the PoW function from "AIIRPoW" to "Proof of Aiir" in the docs; the Rust identifier remains `aiir_pow`. |

---

## 14. Mining command-line experience

The reference daemon `bitaiird` and the CLI client `bitaiir-cli` must
expose mining as a first-class, single-command feature. A user who has
installed BitAiir should be able to start mining with no extra
configuration beyond choosing how many CPU threads to dedicate.

### 14.1 Required commands

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

### 14.2 Embedded mining in the daemon

`bitaiird` must accept a `mine=1` option in `bitaiir.conf` (or an
equivalent CLI flag) that enables mining as part of the running node,
without a separate process. This makes "I run a node, I mine" the
default deployment, matching Bitcoin's `bitcoind -gen` behavior from
its earliest days.

### 14.3 Rationale

BitAiir's design goal of "anyone who can run the daemon can mine"
(section 0) is only real if mining is trivially accessible. If the
only way to mine is to install and configure a separate third-party
miner, the goal is effectively unmet. Bundling mining into the
reference implementation is the practical way to preserve the
"open participation" invariant as the project grows.

Mining is not mandatory — running a non-mining node must remain the
default — but it must be **available with one command**.

---

## 15. Mobile participation

### 15.1 Status

The protocol does not block mining on mobile devices. The 64 MiB
Argon2id memory cost fits comfortably within the per-app memory budget
of any phone with 4 GiB+ of system RAM, which covers essentially every
Android or iOS device sold in the last several years. Modern mobile
CPUs (Apple Silicon, Snapdragon 8 Gen 3, MediaTek Dimensity 9000+)
execute Argon2id at a hashrate comparable to mid-range laptops.

### 15.2 Ecosystem constraints

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

### 15.3 The intended mobile posture

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

### 15.4 Progressive Web App as a future distribution option

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

### 15.5 Summary

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
