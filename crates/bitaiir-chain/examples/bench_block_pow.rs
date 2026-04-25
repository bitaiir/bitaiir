// Measure Argon2id block-PoW hash rate on this machine (production
// parameters: 64 MiB, 1 pass, 1 lane).  Run with:
//
//   cargo run --release -p bitaiir-chain --example bench_block_pow

use std::time::Instant;

use bitaiir_chain::aiir_pow;
use bitaiir_types::{BlockHeader, Hash256};

fn main() {
    println!("Block PoW benchmark (Argon2id 64 MiB + SHA-256d)\n");

    let iterations = 20;
    let mut header = BlockHeader {
        version: 1,
        prev_block_hash: Hash256::from_bytes([0xab; 32]),
        merkle_root: Hash256::from_bytes([0xcd; 32]),
        timestamp: 1_700_000_000,
        bits: 0x2000_ffff,
        nonce: 0,
    };

    let mut times = Vec::with_capacity(iterations);

    for i in 0..iterations {
        header.nonce = i as u32;
        let start = Instant::now();
        let _hash = aiir_pow(&header);
        let elapsed = start.elapsed();
        times.push(elapsed);
    }

    times.sort();
    let total: std::time::Duration = times.iter().sum();
    let avg = total / iterations as u32;
    let median = times[iterations / 2];
    let min = times[0];
    let max = times[iterations - 1];
    let rate = iterations as f64 / total.as_secs_f64();

    println!("  single-thread Argon2id hash rate:");
    println!("    iterations : {iterations}");
    println!("    avg        : {avg:>8.2?}");
    println!("    median     : {median:>8.2?}");
    println!("    min        : {min:>8.2?}");
    println!("    max        : {max:>8.2?}");
    println!("    hash rate  : {rate:.2} h/s");
    println!();

    let current_expected = 256.0;
    let target_5s_1t = 5.0 * rate;
    let target_5s_4t = 5.0 * rate * 4.0;

    println!("  calibration (current target: 1 in {current_expected:.0}):");
    println!("    1 thread,  5s target → 1 in {target_5s_1t:.0} hashes");
    println!("    4 threads, 5s target → 1 in {target_5s_4t:.0} hashes");
    println!();
    println!("    current expected block time:");
    println!("      1 thread  : {:.1}s", current_expected / rate);
    println!("      4 threads : {:.1}s", current_expected / (rate * 4.0));
}
