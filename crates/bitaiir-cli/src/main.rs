//! `bitaiir-cli` — command-line client for the BitAiir daemon.
//!
//! Today this is a placeholder so the workspace builds end-to-end. Once
//! `bitaiir-rpc` exposes a client, this binary will:
//!
//! 1. Parse the requested RPC method and arguments.
//! 2. Read auth/cookie info from the data directory.
//! 3. Send a JSON-RPC request to the running daemon.
//! 4. Print the response (or a friendly error).

fn main() {
    println!("bitaiir-cli: scaffold — RPC client not yet implemented");
}
