# Benchmarks

Two reproducible benches ship in the workspace:

| Bench | What it measures | Why it matters |
|-------|------------------|----------------|
| `bench_block_pow` | Argon2id-based block PoW hash rate (single- and multi-thread) | Tells you how long mining will take; informs initial-difficulty calibration |
| `bench_tx_pow`    | tx-PoW grinding time at priorities 1 / 2 / 5                  | Tells you how snappy `sendtoaddress` will feel on this CPU |

Both run **release-mode only** — the debug build is misleading slow.
Run with the CPU otherwise idle and (on laptops) on AC power so
thermal throttling doesn't dirty the numbers.

## Running

```bash
# Argon2id hash rate, single-thread baseline.
cargo run --release -p bitaiir-chain --example bench_block_pow

# Multi-thread (the realistic mining scenario).
cargo run --release -p bitaiir-chain --example bench_block_pow -- --threads 4

# tx-PoW grind times at priorities 1, 2, 5.
cargo run --release -p bitaiir-chain --example bench_tx_pow
```

The block-PoW bench accepts `--iterations N` to override the default
sample count. Defaults: 20 single-thread, 8 per thread parallel.

## What the numbers mean

### Block PoW (Argon2id 64 MiB + SHA-256d)

The probability that a single hash meets the calibrated initial
target `0x2001fffe` is `1 / 128`. Expected block time on this CPU is
therefore:

```
expected_block_time = 128 / (h/s aggregate across all mining threads)
```

The **per-thread rate degrades under parallelism** because every
mining thread allocates a fresh 64 MiB Argon2id buffer and the CPU's
memory subsystem becomes the bottleneck. On the seed laptop below,
4-thread per-thread throughput is ~52 % of the isolated single-thread
rate — exactly the kind of contention real miners live with.

### tx-PoW (SHA-256d, calibrated 20 leading zero bits)

The probability per hash is `1 / 2^20 ≈ 1 in 1.05 M`. Priority `N`
multiplies the work by `N`, so expected `sendtoaddress` time is:

```
expected_tx_time = N × 2^20 / (double_sha256 h/s)
```

Variance is high — the geometric distribution of PoW gives a long
right tail. Means and medians can differ by 2× even at large sample
sizes; report both.

## Community results

Add a row when you run the benches. Keep the columns aligned and
preserve the sort by aggregate block-PoW rate (highest first).

### `bench_block_pow`

| CPU | Cores / threads used | Single-thread h/s | Aggregate h/s | Per-thread (parallel) | Proj. block time | Date | Reporter |
|-----|---------------------|-------------------|---------------|-----------------------|------------------|------|----------|
| Intel i5-8265U (Whiskey Lake, no SHA-NI) | 4 / 4 | 11.9 | 24.8 | 6.2 | ~5.2 s | 2026-04-25 | @eduardodoege |

### `bench_tx_pow`

Numbers are **median** drip times at the listed priority on an idle
CPU. During real mining, contention typically pushes these 2–4×
higher.

| CPU | Priority 1 (median) | Priority 2 (median) | Priority 5 (median) | Hash rate | Date | Reporter |
|-----|---------------------|---------------------|---------------------|-----------|------|----------|
| Intel i5-8265U | 0.75 s | 2.69 s | 3.42 s | ~0.85 Mh/s | 2026-04-25 | @eduardodoege |

## Reproducibility checklist

Before adding a row:

- [ ] Built with `cargo build --release` (or `cargo run --release`).
- [ ] Other CPU-heavy processes closed; laptop on AC power.
- [ ] Same `bitaiir-chain` revision as upstream `master` (or note the
      commit hash in the row's reporter column).
- [ ] If a row diverges by >2× from a similar CPU already listed,
      double-check thermal throttling and re-run.

## Contributing a row

Open a PR adding your row to the appropriate table. Single-line
diff, no other changes — the maintainers won't gate it on
verification but reserve the right to re-test if a number looks off.
