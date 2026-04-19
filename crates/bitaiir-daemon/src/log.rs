//! Unified logging for the BitAiir daemon.
//!
//! Two output targets, one function call:
//!
//! - **Terminal** (stdout): always printed, both daemon and
//!   interactive modes.  Visible before the TUI takes over and
//!   again after it exits.
//! - **TUI log pane** (via `events` channel): only in interactive
//!   mode.  The TUI's `push_log` displays whatever string it
//!   receives — the formatting is already baked in here.
//!
//! Two function families:
//!
//! - [`print_line`]: plain text (startup banner, data tables,
//!   JSON command output).  No timestamp, no level prefix.
//! - [`log_info`] / [`log_warn`]: timestamped `LEVEL message`
//!   lines with ANSI color.

use std::sync::mpsc::Sender;

const DIM: &str = "\x1b[90m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";

/// Print a plain line (no timestamp, no level).  When `events` is
/// `Some` we're in interactive mode: the line goes only to the TUI
/// log channel, because `println!` during the TUI's lifetime writes
/// to the alternate-screen buffer and is wiped on exit.  The TUI
/// replays its buffer to stdout after `LeaveAlternateScreen`, so the
/// user sees every line once.  When `events` is `None` (daemon mode
/// without TUI) we `println!` directly.
pub fn print_line(msg: &str, events: &Option<Sender<String>>) {
    match events {
        Some(ev) => {
            let _ = ev.send(msg.to_string());
        }
        None => {
            println!("{msg}");
        }
    }
}

/// Log an INFO-level event: `<dim timestamp>  <green INFO> message`.
/// Routing follows [`print_line`]: TUI channel when interactive,
/// stdout otherwise.
pub fn log_info(msg: &str, events: &Option<Sender<String>>) {
    let ts = iso_utc_now();
    let line = format!("{DIM}{ts}{RESET}  {GREEN}INFO{RESET} {msg}");
    match events {
        Some(ev) => {
            let _ = ev.send(line);
        }
        None => {
            println!("{line}");
        }
    }
}

/// Log a WARN-level event: `<dim timestamp>  <yellow WARN> message`.
/// Routing follows [`print_line`]: TUI channel when interactive,
/// stdout otherwise.
pub fn log_warn(msg: &str, events: &Option<Sender<String>>) {
    let ts = iso_utc_now();
    let line = format!("{DIM}{ts}{RESET}  {YELLOW}WARN{RESET} {msg}");
    match events {
        Some(ev) => {
            let _ = ev.send(line);
        }
        None => {
            println!("{line}");
        }
    }
}

/// ISO 8601 UTC timestamp without sub-second precision.
fn iso_utc_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let time_of_day = secs % 86400;
    let h = time_of_day / 3600;
    let m = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;
    let days = secs / 86400;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut y = 1970u64;
    loop {
        let dy = if is_leap(y) { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        y += 1;
    }
    let leap = is_leap(y);
    let mdays = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut mo = 0u64;
    for (i, &md) in mdays.iter().enumerate() {
        if days < md {
            mo = i as u64 + 1;
            break;
        }
        days -= md;
    }
    (y, mo, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
