// Measure Argon2id block-PoW hash rate on this machine (production
// parameters: 64 MiB, 1 pass, 1 lane).
//
// Usage:
//   cargo run --release -p bitaiir-chain --example bench_block_pow
//   cargo run --release -p bitaiir-chain --example bench_block_pow -- --threads 4
//   cargo run --release -p bitaiir-chain --example bench_block_pow -- --threads 4 --iterations 10
//
// The single-thread number is a clean baseline.  The multi-thread
// number is what real mining sees (memory bandwidth contention from
// 4× 64 MiB Argon2id buffers running in parallel typically pushes
// per-thread throughput well below the isolated rate).

use std::sync::Arc;
use std::time::Instant;

use bitaiir_chain::aiir_pow;
use bitaiir_types::{BlockHeader, Hash256};

/// Number of leading zero bits in BitAiir's calibrated initial
/// difficulty (`0x2001fffe`, ~1 in 128 hashes).
const INITIAL_DIFFICULTY_INV: f64 = 128.0;
const TARGET_BLOCK_TIME_SEC: f64 = 5.0;

fn parse_args() -> (usize, usize) {
    let mut threads: usize = 1;
    let mut iterations: usize = 0; // 0 = pick a sensible default per mode
    let argv: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--threads" => {
                threads = argv
                    .get(i + 1)
                    .and_then(|s| s.parse().ok())
                    .expect("--threads expects a positive integer");
                i += 2;
            }
            "--iterations" => {
                iterations = argv
                    .get(i + 1)
                    .and_then(|s| s.parse().ok())
                    .expect("--iterations expects a positive integer");
                i += 2;
            }
            "--help" | "-h" => {
                eprintln!("usage: bench_block_pow [--threads N] [--iterations N]");
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    if threads == 0 {
        eprintln!("--threads must be >= 1");
        std::process::exit(2);
    }
    if iterations == 0 {
        // Default keeps each run under ~30 s of wall time on a
        // mid-range CPU: a few hashes per thread is plenty for the
        // mean-rate signal, and the mode-2 outputs converge fast.
        iterations = if threads == 1 { 20 } else { 8 };
    }
    (threads, iterations)
}

fn make_header(thread_id: u32, nonce: u32) -> BlockHeader {
    BlockHeader {
        version: 1,
        // Different prev_block_hash per thread so Argon2id salts
        // differ, preventing the OS from cache-sharing memory pages
        // between threads (which would inflate the apparent rate).
        prev_block_hash: Hash256::from_bytes([thread_id as u8 ^ 0xab; 32]),
        merkle_root: Hash256::from_bytes([0xcd; 32]),
        timestamp: 1_700_000_000,
        bits: 0x2001_fffe,
        nonce,
    }
}

fn bench_single(iterations: usize) -> f64 {
    let mut header = make_header(0, 0);
    let mut times = Vec::with_capacity(iterations);
    for i in 0..iterations {
        header.nonce = i as u32;
        let start = Instant::now();
        let _hash = aiir_pow(&header);
        times.push(start.elapsed());
    }
    times.sort();
    let total: std::time::Duration = times.iter().sum();
    let avg = total / iterations as u32;
    let median = times[iterations / 2];
    let min = times[0];
    let max = times[iterations - 1];
    let rate = iterations as f64 / total.as_secs_f64();

    println!("  single-thread Argon2id (memory-hard, no contention):");
    println!("    iterations : {iterations}");
    println!("    avg        : {avg:>8.2?}");
    println!("    median     : {median:>8.2?}");
    println!("    min        : {min:>8.2?}");
    println!("    max        : {max:>8.2?}");
    println!("    hash rate  : {rate:.2} h/s");
    rate
}

fn bench_parallel(threads: usize, iterations_per_thread: usize) -> f64 {
    let total_hashes = threads * iterations_per_thread;
    let start = Instant::now();
    let handles: Vec<_> = (0..threads)
        .map(|tid| {
            let n = iterations_per_thread;
            std::thread::spawn(move || {
                let mut header = make_header(tid as u32, 0);
                for nonce in 0..n {
                    header.nonce = nonce as u32;
                    // Drop the result so the optimizer doesn't elide
                    // the work.
                    let _h = aiir_pow(&header);
                    std::hint::black_box(&_h);
                }
            })
        })
        .collect();
    for h in handles {
        let _ = h.join();
    }
    let elapsed = start.elapsed();
    let rate = total_hashes as f64 / elapsed.as_secs_f64();
    let per_thread = rate / threads as f64;

    println!();
    println!("  parallel Argon2id ({threads} threads, memory-bandwidth limited):");
    println!("    iterations : {iterations_per_thread} per thread = {total_hashes} total");
    println!("    wall time  : {elapsed:>8.2?}");
    println!("    aggregate  : {rate:.2} h/s");
    println!("    per thread : {per_thread:.2} h/s");
    rate
}

fn main() {
    let (threads, iterations) = parse_args();

    println!("Block PoW benchmark (Argon2id 64 MiB + SHA-256d)\n");
    let _hold: Arc<()> = Arc::new(()); // keep ownership semantics tidy

    let single_rate = bench_single(iterations);

    let aggregate_rate = if threads > 1 {
        bench_parallel(threads, iterations)
    } else {
        single_rate
    };

    println!();
    println!("  calibration vs initial difficulty (1 hash in {INITIAL_DIFFICULTY_INV:.0}):");
    let block_time_single = INITIAL_DIFFICULTY_INV / single_rate;
    println!("    1 thread   : ~{block_time_single:.1}s expected per block");
    if threads > 1 {
        let block_time_par = INITIAL_DIFFICULTY_INV / aggregate_rate;
        println!("    {threads} threads  : ~{block_time_par:.1}s expected per block");
    }
    println!("    target     : ~{TARGET_BLOCK_TIME_SEC:.0}s per block");
}
