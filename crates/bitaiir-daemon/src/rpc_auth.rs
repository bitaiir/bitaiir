//! RPC authentication — cookie generation and credential resolution.
//!
//! BitAiir follows Bitcoin Core's cookie-auth pattern: on startup
//! the daemon writes a random credential to `<data_dir>/.cookie` as
//!
//! ```text
//! __cookie__:<base64 random bytes>
//! ```
//!
//! The `bitaiir-cli` and the built-in TUI read the same file and
//! include it as HTTP Basic Auth (`Authorization: Basic <b64>`) on
//! every RPC request.  The cookie is regenerated on every daemon
//! startup and deleted on clean shutdown, so stale credentials
//! never linger on disk.
//!
//! If the operator sets explicit `rpc.user` and `rpc.password` in
//! `bitaiir.toml` — useful for LAN-exposed RPC where clients can't
//! read a local file — the cookie file is NOT written; those
//! credentials are used instead.
//!
//! Cookie user is always the literal `__cookie__`; only the
//! password portion is random.  Clients need no knowledge of the
//! username convention beyond reading and forwarding the whole
//! line.

use base64::Engine;
use rand::RngCore;
use std::path::{Path, PathBuf};

/// Fixed username for the cookie-auth mechanism.  Matches Bitcoin
/// Core so tooling that speaks that protocol works unchanged.
pub const COOKIE_USER: &str = "__cookie__";

/// Relative file name of the cookie within the data dir.
pub const COOKIE_FILENAME: &str = ".cookie";

/// Resolved RPC credentials for this process lifetime.
///
/// - `user` + `password` are what the server validates against and
///   what clients pass via `Authorization: Basic <b64(user:pass)>`.
/// - `cookie_path` is `Some(...)` when the daemon generated a
///   cookie file that it owns and should delete on shutdown; it's
///   `None` when credentials came from config and no file was
///   written.
pub struct RpcCredentials {
    pub user: String,
    pub password: String,
    pub cookie_path: Option<PathBuf>,
}

impl RpcCredentials {
    /// Format `user:password` as an HTTP Basic Auth token (without
    /// the `Basic ` prefix).  Only the TUI self-connects to its
    /// own RPC, so this helper is gated behind the `tui` feature —
    /// external callers use `bitaiir-cli`, which computes its own
    /// token.
    #[cfg(feature = "tui")]
    pub fn basic_token(&self) -> String {
        let raw = format!("{}:{}", self.user, self.password);
        base64::engine::general_purpose::STANDARD.encode(raw)
    }
}

/// Resolve RPC credentials from config, generating a cookie file
/// if no explicit user/password were set.
///
/// Returns an error if the data dir can't be created or the cookie
/// file can't be written.
pub fn resolve_credentials(
    data_dir: &Path,
    cfg_user: Option<&str>,
    cfg_password: Option<&str>,
) -> std::io::Result<RpcCredentials> {
    match (cfg_user, cfg_password) {
        (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => Ok(RpcCredentials {
            user: u.to_string(),
            password: p.to_string(),
            cookie_path: None,
        }),
        _ => {
            std::fs::create_dir_all(data_dir)?;
            let cookie_path = data_dir.join(COOKIE_FILENAME);
            let password = generate_cookie();
            // Write the `user:password` tuple as a single line so a
            // client can slurp the whole file and feed it straight
            // into an HTTP Basic header.
            let contents = format!("{COOKIE_USER}:{password}");
            std::fs::write(&cookie_path, &contents)?;
            // On Unix restrict the file to owner-only.  On Windows
            // the user's profile directory is already per-user.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&cookie_path)?.permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(&cookie_path, perms)?;
            }
            Ok(RpcCredentials {
                user: COOKIE_USER.to_string(),
                password,
                cookie_path: Some(cookie_path),
            })
        }
    }
}

/// Best-effort delete of the cookie file on shutdown.  Swallowed
/// errors are logged by the caller.
pub fn clear_cookie(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Generate 32 random bytes and base64-encode them as the cookie
/// password.  Base64 (not URL-safe) keeps the output ASCII so a
/// copy/paste diagnostic doesn't accidentally introduce escape
/// characters.
fn generate_cookie() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
