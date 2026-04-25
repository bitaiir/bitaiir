// Measure tx-PoW mining time on this machine at production difficulty
// (20 leading zero bits).  Run with:
//
//   cargo run --release -p bitaiir-chain --example bench_tx_pow

use std::time::{Duration, Instant};

use bitaiir_chain::{mine_tx_pow_with_priority, validate_tx_pow};
use bitaiir_types::{Amount, Hash256, OutPoint, Transaction, TxIn, TxOut};

fn make_tx(seed: u8) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            prev_out: OutPoint {
                txid: Hash256::from_bytes([seed; 32]),
                vout: 0,
            },
            signature: vec![0xaa; 64],
            pubkey: vec![0x02; 33],
            sequence: u32::MAX,
        }],
        outputs: vec![TxOut::p2pkh(
            Amount::from_atomic(50 * 100_000_000),
            [0x99; 20],
        )],
        locktime: 0,
        pow_nonce: 0,
        pow_priority: 0,
    }
}

fn bench_priority(priority: u64, iterations: usize) {
    let mut times = Vec::with_capacity(iterations);
    let mut nonces = Vec::with_capacity(iterations);

    for i in 0..iterations {
        let mut tx = make_tx(i as u8);
        let start = Instant::now();
        mine_tx_pow_with_priority(&mut tx, priority);
        let elapsed = start.elapsed();
        assert!(validate_tx_pow(&tx));
        nonces.push(tx.pow_nonce);
        times.push(elapsed);
    }

    times.sort();
    let total: Duration = times.iter().sum();
    let avg = total / iterations as u32;
    let median = times[iterations / 2];
    let min = times[0];
    let max = times[iterations - 1];

    let avg_nonce: u64 = nonces.iter().sum::<u64>() / iterations as u64;
    let avg_hashrate = avg_nonce as f64 / avg.as_secs_f64();

    println!("  priority {priority}:");
    println!("    iterations : {iterations}");
    println!("    avg        : {avg:>8.2?}");
    println!("    median     : {median:>8.2?}");
    println!("    min        : {min:>8.2?}");
    println!("    max        : {max:>8.2?}");
    println!("    avg nonce  : {avg_nonce}");
    println!("    hash rate  : {:.2} Mh/s", avg_hashrate / 1_000_000.0);
}

fn main() {
    println!("tx-PoW benchmark (production target: 20 leading zero bits)\n");

    println!("--- priority 1 (minimum, target ~1s) ---");
    bench_priority(1, 10);

    println!("\n--- priority 2 (~2x CPU) ---");
    bench_priority(2, 5);

    println!("\n--- priority 5 (~5x CPU) ---");
    bench_priority(5, 3);
}
