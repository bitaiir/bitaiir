//! Interactive REPL with software scroll and custom text selection.
//!
//! Architecture (inspired by Claude Code's `Ink` renderer):
//!
//!   - Alternate screen + full mouse capture (SGR modes).  The whole
//!     terminal is ours; nothing leaks into scrollback.
//!   - Line-based log buffer (`Vec<String>`) with a scroll offset.
//!     Viewport culling renders `lines[off .. off + height]`.
//!   - Anchor/focus selection model: click starts, drag extends, release
//!     finishes and copies to the system clipboard via `arboard`.
//!     Double-click = word, triple-click = line.
//!   - Full-frame render on every dirty tick, wrapped in DEC 2026
//!     synchronized-output markers so supported terminals never tear.
//!
//! Nothing here is trying to be a general-purpose TUI framework — it's
//! the minimum needed for a mining log view with a prompt at the bottom.

use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use crossterm::cursor::{Hide, MoveTo, Show};
use crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event, KeyCode, KeyEventKind, KeyModifiers, MouseButton, MouseEventKind,
};
use crossterm::style::Print;
use crossterm::terminal::{
    self, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use crossterm::{execute, queue};

// --- ANSI colors --------------------------------------------------------- //

const BLUE: &str = "\x1b[38;2;18;148;215m";
const RED: &str = "\x1b[38;2;240;80;80m";
const DIM: &str = "\x1b[90m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

/// Inverse video ON / OFF — used to highlight selected cells.
const INV_ON: &str = "\x1b[7m";
const INV_OFF: &str = "\x1b[27m";

/// Rows of fixed "chrome" around the log viewport: 1 top border,
/// 1 separator, 1 input, 1 bottom border.
const CHROME_ROWS: u16 = 4;

/// Rows the mouse wheel scrolls per event.
const WHEEL_STEP: usize = 3;

/// Max milliseconds between clicks to count as a multi-click.
const MULTI_CLICK_MS: u128 = 500;

// --- Commands ------------------------------------------------------------ //

const COMMANDS: &[(&str, &str)] = &[
    ("getblockchaininfo", "Show chain status"),
    ("getblock", "Show block at height"),
    ("getnewaddress", "Generate a new address"),
    ("getbalance", "Show address balance"),
    ("listaddresses", "List all wallet addresses"),
    ("sendtoaddress", "Send AIIR to address"),
    ("getmempoolinfo", "Show mempool status"),
    ("gettransaction", "Look up tx by txid"),
    ("gettransactionhistory", "Tx history for address"),
    ("mine-start", "Start mining"),
    ("mine-stop", "Stop mining"),
    ("addpeer", "Connect to a peer"),
    ("listpeers", "Show connected peers"),
    ("listknownpeers", "Show all known peers"),
    ("encryptwallet", "Encrypt wallet with passphrase"),
    ("walletpassphrase", "Unlock wallet for N seconds"),
    ("walletlock", "Lock wallet immediately"),
    ("stop", "Stop the daemon"),
    ("help", "Show all commands"),
    ("exit", "Exit BitAiir"),
];

// --- Data model ---------------------------------------------------------- //

/// All log lines + current scroll position.
struct LogBuffer {
    lines: Vec<String>,
    /// Index into `lines` of the first visible row.
    scroll_offset: usize,
    /// True when the viewport is pinned to the bottom (auto-follow).
    sticky: bool,
}

impl LogBuffer {
    fn new() -> Self {
        Self {
            lines: Vec::new(),
            scroll_offset: 0,
            sticky: true,
        }
    }

    fn push(&mut self, line: String, viewport_height: usize) {
        self.lines.push(line);
        if self.sticky {
            self.scroll_to_bottom(viewport_height);
        }
    }

    fn scroll_to_bottom(&mut self, viewport_height: usize) {
        self.scroll_offset = self.lines.len().saturating_sub(viewport_height);
        self.sticky = true;
    }

    fn scroll_up(&mut self, by: usize) {
        self.scroll_offset = self.scroll_offset.saturating_sub(by);
        self.sticky = false;
    }

    fn scroll_down(&mut self, by: usize, viewport_height: usize) {
        let max = self.lines.len().saturating_sub(viewport_height);
        self.scroll_offset = (self.scroll_offset + by).min(max);
        self.sticky = self.scroll_offset >= max;
    }
}

/// Buffer-space coordinate (row is an index into `LogBuffer::lines`,
/// col is a visible character offset into that line).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
struct Point {
    row: usize,
    col: usize,
}

impl Point {
    fn before(&self, other: &Self) -> bool {
        (self.row, self.col) <= (other.row, other.col)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SelectionMode {
    Char,
    Word,
    Line,
}

/// Anchor + focus selection. `None` for both means no selection.
struct Selection {
    anchor: Option<Point>,
    focus: Option<Point>,
    dragging: bool,
    mode: SelectionMode,
    /// For word / line mode: the span selected by the multi-click.
    /// Drag extensions grow away from this span, never shrink it.
    anchor_span: Option<(Point, Point)>,
}

impl Selection {
    fn new() -> Self {
        Self {
            anchor: None,
            focus: None,
            dragging: false,
            mode: SelectionMode::Char,
            anchor_span: None,
        }
    }

    fn clear(&mut self) {
        self.anchor = None;
        self.focus = None;
        self.dragging = false;
        self.mode = SelectionMode::Char;
        self.anchor_span = None;
    }

    fn active(&self) -> bool {
        self.anchor.is_some() && self.focus.is_some()
    }

    /// Return the selection as (start, end) with `start.before(end)`.
    fn normalized(&self) -> Option<(Point, Point)> {
        let a = self.anchor?;
        let f = self.focus?;
        if a.before(&f) {
            Some((a, f))
        } else {
            Some((f, a))
        }
    }

    /// Selection range on a given buffer row, as a half-open `[start, end)`
    /// in visible columns, or `None` if the row has no selection.
    fn range_on_row(&self, row: usize) -> Option<(usize, usize)> {
        let (s, e) = self.normalized()?;
        if row < s.row || row > e.row {
            return None;
        }
        let col_start = if row == s.row { s.col } else { 0 };
        let col_end = if row == e.row { e.col } else { usize::MAX };
        if col_start >= col_end {
            None
        } else {
            Some((col_start, col_end))
        }
    }
}

/// Open a direct, unbuffered handle to the controlling terminal.
///
/// Rust's `io::stdout()` pipes through a `LineWriter` whose internal
/// buffer is 1 KiB, and on Windows the UTF-8 → UTF-16 conversion caps
/// each `WriteConsoleW` call at 4096 wchars.  A 9 KiB frame therefore
/// reaches Windows Terminal as 2-3 separate syscalls, and WT renders
/// each chunk as it arrives — that's where the mid-frame cursor
/// flashes came from.  Opening `CONOUT$` directly gives us a `File`
/// that uses `WriteFile`, which takes the whole buffer in one call.
#[cfg(windows)]
fn open_terminal_writer() -> Option<std::fs::File> {
    use std::os::windows::io::AsRawHandle;

    let f = std::fs::OpenOptions::new()
        .write(true)
        .open("CONOUT$")
        .ok()?;

    // The fresh handle does *not* inherit stdout's console mode, so we
    // need to turn on virtual-terminal processing ourselves — otherwise
    // our ANSI escape sequences are written as literal text.
    unsafe {
        let h = f.as_raw_handle() as winapi::HANDLE;
        let mut mode: u32 = 0;
        if winapi::GetConsoleMode(h, &mut mode) == 0 {
            return None;
        }
        let new_mode =
            mode | winapi::ENABLE_PROCESSED_OUTPUT | winapi::ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        if winapi::SetConsoleMode(h, new_mode) == 0 {
            return None;
        }
    }
    Some(f)
}

#[cfg(not(windows))]
fn open_terminal_writer() -> Option<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .ok()
}

#[cfg(windows)]
#[allow(non_camel_case_types, non_snake_case, clippy::upper_case_acronyms)]
mod winapi {
    use std::ffi::c_void;

    pub type HANDLE = *mut c_void;
    pub const ENABLE_PROCESSED_OUTPUT: u32 = 0x0001;
    pub const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;

    unsafe extern "system" {
        pub fn GetConsoleMode(hConsoleHandle: HANDLE, lpMode: *mut u32) -> i32;
        pub fn SetConsoleMode(hConsoleHandle: HANDLE, dwMode: u32) -> i32;
    }
}

/// Top-level app state.
struct App {
    input: String,
    cursor: usize,
    history: Vec<String>,
    history_idx: Option<usize>,
    autocomplete: bool,
    autocomplete_idx: usize,
    cols: u16,
    rows: u16,
    dirty: bool,
    /// When true, the next render repaints every row; when false, it
    /// only rewrites the input line.  Typing only needs the small
    /// partial redraw — repainting the whole 5 KiB frame for every
    /// keystroke is what the user was seeing as a mid-box flash.
    full_redraw: bool,
    buffer: LogBuffer,
    selection: Selection,
    /// For multi-click detection: last click's (col, row, time).
    last_click: Option<(u16, u16, Instant)>,
    click_count: u32,
    clipboard: Option<arboard::Clipboard>,
    /// When set, keyboard events are suppressed until this instant.
    /// Windows Terminal's right-click "paste" bypasses bracketed-paste
    /// mode and injects clipboard text as raw key events.  We detect
    /// the right-click and swallow everything for a short window.
    suppress_keys_until: Option<Instant>,
    /// Unbuffered direct-to-terminal writer (see `open_terminal_writer`).
    term: Option<std::fs::File>,
}

impl App {
    fn new(cols: u16, rows: u16) -> Self {
        Self {
            input: String::new(),
            cursor: 0,
            history: Vec::new(),
            history_idx: None,
            autocomplete: false,
            autocomplete_idx: 0,
            cols,
            rows,
            dirty: true,
            full_redraw: true,
            buffer: LogBuffer::new(),
            selection: Selection::new(),
            last_click: None,
            click_count: 0,
            clipboard: arboard::Clipboard::new().ok(),
            suppress_keys_until: None,
            term: open_terminal_writer(),
        }
    }

    fn viewport_height(&self) -> usize {
        self.rows.saturating_sub(CHROME_ROWS) as usize
    }

    /// First screen row (0-based) of the log viewport.
    fn log_top(&self) -> u16 {
        1
    }

    /// Last screen row (0-based) of the log viewport.
    fn log_bottom(&self) -> u16 {
        self.rows.saturating_sub(CHROME_ROWS + 1) + 1
    }

    fn insert_char(&mut self, c: char) {
        self.input.insert(self.cursor, c);
        self.cursor += c.len_utf8();
        self.dirty = true;
    }

    fn delete_char(&mut self) {
        if self.cursor > 0 {
            let prev = self.input[..self.cursor]
                .chars()
                .last()
                .map(|c| c.len_utf8())
                .unwrap_or(0);
            self.cursor -= prev;
            self.input.remove(self.cursor);
            self.dirty = true;
        }
    }

    fn set_input(&mut self, s: String) {
        self.cursor = s.len();
        self.input = s;
        self.dirty = true;
    }

    fn clear_input(&mut self) {
        self.input.clear();
        self.cursor = 0;
        self.dirty = true;
    }

    fn push_log(&mut self, line: String) {
        let h = self.viewport_height();
        self.buffer.push(line, h);
        self.dirty = true;
        self.full_redraw = true;
    }

    /// Mark everything as needing a redraw (scroll, autocomplete,
    /// selection, resize, new log line — anything besides pure input
    /// editing).
    fn mark_full(&mut self) {
        self.dirty = true;
        self.full_redraw = true;
    }
}

// --- Helpers ------------------------------------------------------------- //

/// Number of visible characters in a string (ignores ANSI escape sequences).
fn visible_len(s: &str) -> usize {
    let mut len = 0;
    let mut in_esc = false;
    for c in s.chars() {
        if in_esc {
            if c.is_ascii_alphabetic() {
                in_esc = false;
            }
        } else if c == '\x1b' {
            in_esc = true;
        } else {
            len += 1;
        }
    }
    len
}

/// Return the string with ANSI escape sequences removed.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_esc = false;
    for c in s.chars() {
        if in_esc {
            if c.is_ascii_alphabetic() {
                in_esc = false;
            }
        } else if c == '\x1b' {
            in_esc = true;
        } else {
            out.push(c);
        }
    }
    out
}

/// Apply inverse-video SGR to the visible columns in `[col_start, col_end)`
/// of `content`, passing through any ANSI escape sequences unchanged.
fn apply_selection(content: &str, col_start: usize, col_end: usize) -> String {
    let mut out = String::with_capacity(content.len() + 16);
    let mut col = 0usize;
    let mut in_esc = false;
    let mut selected = false;
    for c in content.chars() {
        if in_esc {
            out.push(c);
            if c.is_ascii_alphabetic() {
                in_esc = false;
            }
            continue;
        }
        if c == '\x1b' {
            out.push(c);
            in_esc = true;
            continue;
        }
        let should = col >= col_start && col < col_end;
        if should && !selected {
            out.push_str(INV_ON);
            selected = true;
        } else if !should && selected {
            out.push_str(INV_OFF);
            selected = false;
        }
        out.push(c);
        col += 1;
    }
    if selected {
        out.push_str(INV_OFF);
    }
    out
}

/// Full validation of a BitAiir address: prefix + base58check + length.
/// Catches typos (checksum mismatch) and garbled input, not just missing prefix.
fn is_valid_address(addr: &str) -> bool {
    let Some(body) = addr.strip_prefix("aiir") else {
        return false;
    };
    let Ok(decoded) = bitaiir_crypto::base58::decode_check(body) else {
        return false;
    };
    decoded.len() == 21
}

/// Wrap `content` in side borders `│ … │` padded to `cols` visible columns.
/// `right` is the pre-formatted (ANSI-styled) right-edge character, so the
/// caller can substitute a scrollbar thumb for the normal `│`.
fn bordered_with(content: &str, cols: u16, right: &str) -> String {
    let w = cols as usize;
    if w < 6 {
        return String::new();
    }
    let inner = w - 4;
    let vlen = visible_len(content);
    let pad = inner.saturating_sub(vlen);
    format!("{DIM}│{RESET} {content}{} {right}", " ".repeat(pad))
}

/// Shortcut for a line with the default right border.
fn bordered(content: &str, cols: u16) -> String {
    bordered_with(content, cols, &format!("{DIM}│{RESET}"))
}

/// Compute the (start, end) row range — in viewport coordinates — that
/// the scrollbar thumb covers.  Returns an empty range when no scrollbar
/// is needed (all content fits on screen).
fn thumb_range(scroll_offset: usize, total: usize, height: usize) -> (usize, usize) {
    if total <= height || height == 0 {
        return (0, 0);
    }
    let thumb_size = ((height * height) / total).max(1);
    let max_scroll = total - height;
    let thumb_start = if max_scroll > 0 {
        (scroll_offset * (height.saturating_sub(thumb_size))) / max_scroll
    } else {
        0
    };
    let thumb_end = (thumb_start + thumb_size).min(height);
    (thumb_start, thumb_end)
}

fn filter_commands(prefix: &str) -> Vec<(&'static str, &'static str)> {
    COMMANDS
        .iter()
        .filter(|(name, _)| prefix.is_empty() || name.starts_with(prefix))
        .copied()
        .collect()
}

/// iTerm2-style word-class: spaces / identifiers / punctuation.
fn char_class(c: char) -> u8 {
    if c == ' ' {
        0
    } else if c.is_alphanumeric() || "/-+~_.\\".contains(c) {
        1
    } else {
        2
    }
}

/// Given a buffer line and a column, return the `(start, end)` range
/// of the word under `col` (in visible-column units, half-open).
fn word_range(line: &str, col: usize) -> (usize, usize) {
    let stripped = strip_ansi(line);
    let chars: Vec<char> = stripped.chars().collect();
    if chars.is_empty() || col >= chars.len() {
        return (col, col);
    }
    let target = char_class(chars[col]);
    let mut start = col;
    while start > 0 && char_class(chars[start - 1]) == target {
        start -= 1;
    }
    let mut end = col + 1;
    while end < chars.len() && char_class(chars[end]) == target {
        end += 1;
    }
    (start, end)
}

/// Extract visible columns `[start, end)` from an ANSI-styled line.
fn slice_visible(content: &str, start: usize, end: usize) -> String {
    let mut out = String::new();
    let mut col = 0usize;
    let mut in_esc = false;
    for c in content.chars() {
        if in_esc {
            if c.is_ascii_alphabetic() {
                in_esc = false;
            }
            continue;
        }
        if c == '\x1b' {
            in_esc = true;
            continue;
        }
        if col >= start && col < end {
            out.push(c);
        }
        col += 1;
        if col >= end {
            break;
        }
    }
    out
}

/// Visible length of a line in the buffer (without ANSI).
fn line_visible_len(line: &str) -> usize {
    visible_len(line)
}

// --- Coordinate mapping -------------------------------------------------- //

/// Map a screen point to a buffer point, clamped to valid positions.
/// Returns `None` if the screen point is outside the log viewport.
fn screen_to_buffer(screen_col: u16, screen_row: u16, app: &App) -> Option<Point> {
    let top = app.log_top();
    let bot = app.log_bottom();
    if screen_row < top || screen_row > bot {
        return None;
    }
    // Inner content starts after "│ " (cols 0..=1).
    if screen_col < 2 {
        return None;
    }
    let col = (screen_col - 2) as usize;
    let row_in_view = (screen_row - top) as usize;
    let buf_row = app.buffer.scroll_offset + row_in_view;
    Some(Point { row: buf_row, col })
}

// --- Rendering ----------------------------------------------------------- //

/// Format the top border with the app title embedded.
fn render_top_border(cols: u16) -> String {
    let w = cols as usize;
    if w < 30 {
        return format!("{DIM}╭{}╮{RESET}", "─".repeat(w.saturating_sub(2)));
    }
    // Visible prefix: "╭─── BitAiir Core v0.1.0 " = 25 chars
    let prefix_vis = 25;
    let fill = w.saturating_sub(prefix_vis + 1);
    format!(
        "{DIM}╭─── {BLUE}{BOLD}BitAiir Core v0.1.0{RESET}{DIM} {}╮{RESET}",
        "─".repeat(fill)
    )
}

/// Render the full frame.
///
/// The whole frame is built into a local `Vec<u8>` and shipped to the
/// terminal with a single `write_all` on the direct `CONOUT$` /
/// `/dev/tty` handle.  Rust's `io::stdout()` buffers through a 1 KiB
/// `LineWriter`, so a 9 KiB frame is split into several syscalls and
/// Windows Terminal renders each chunk as it arrives — that's what the
/// cursor flash was.  Going around stdout entirely makes every frame
/// land atomically.
fn render_frame(app: &mut App) -> io::Result<()> {
    let w = app.cols;
    let rows = app.rows;
    let log_top = app.log_top();
    let log_bot = app.log_bottom();
    let height = app.viewport_height();

    let mut out: Vec<u8> = Vec::with_capacity(16 * 1024);

    // Begin synchronized output.  The cursor is already hidden via
    // `execute!(..., Hide)` at startup and stays hidden for the whole
    // TUI lifetime, so we don't re-send the hide sequence every frame.
    out.extend_from_slice(b"\x1b[?2026h");

    // Top border.  Every drawn row fills the full terminal width,
    // so an explicit `Clear` before each `Print` is redundant and
    // only adds a blank-line instant that Windows Terminal may flash.
    queue!(out, MoveTo(0, 0))?;
    queue!(out, Print(render_top_border(w)))?;

    // Log viewport.
    let buf = &app.buffer;
    let end = (buf.scroll_offset + height).min(buf.lines.len());
    let visible_slice: &[String] = if buf.scroll_offset < buf.lines.len() {
        &buf.lines[buf.scroll_offset..end]
    } else {
        &[]
    };

    // Scrollbar: compute thumb row range over the viewport.
    let (thumb_start, thumb_end) = thumb_range(buf.scroll_offset, buf.lines.len(), height);
    let normal_right = format!("{DIM}│{RESET}");
    let thumb_right = format!("{BLUE}┃{RESET}");

    for i in 0..height {
        let row = log_top + i as u16;
        queue!(out, MoveTo(0, row))?;

        let line = if i < visible_slice.len() {
            visible_slice[i].as_str()
        } else {
            ""
        };
        let buf_row = buf.scroll_offset + i;

        let right = if i >= thumb_start && i < thumb_end {
            &thumb_right
        } else {
            &normal_right
        };

        let rendered = if let Some((s, e)) = app.selection.range_on_row(buf_row) {
            let vlen = line_visible_len(line);
            let e_clamped = e.min(vlen);
            if s >= e_clamped {
                bordered_with(line, w, right)
            } else {
                let styled = apply_selection(line, s, e_clamped);
                bordered_with(&styled, w, right)
            }
        } else {
            bordered_with(line, w, right)
        };
        queue!(out, Print(rendered))?;
    }

    // Autocomplete overlay (drawn over the bottom of the log viewport).
    if app.autocomplete {
        render_autocomplete(&mut out, app, log_bot)?;
    }

    // Separator.
    queue!(out, MoveTo(0, rows - 3))?;
    queue!(
        out,
        Print(format!(
            "{DIM}├{}┤{RESET}",
            "─".repeat((w as usize).saturating_sub(2))
        ))
    )?;

    // Input line (visual cursor drawn inline via inverse video).
    append_input_line(&mut out, app)?;

    // Bottom border.
    queue!(out, MoveTo(0, rows - 1))?;
    queue!(
        out,
        Print(format!(
            "{DIM}╰{}╯{RESET}",
            "─".repeat((w as usize).saturating_sub(2))
        ))
    )?;

    // Park the (hidden) cursor somewhere stable.
    queue!(out, MoveTo(0, rows - 2))?;

    // End synchronized output.
    out.extend_from_slice(b"\x1b[?2026l");

    // Single atomic write: the whole frame reaches the terminal as one
    // burst, so the real cursor never peeks through mid-render.
    if let Some(term) = app.term.as_mut() {
        term.write_all(&out)?;
        term.flush()?;
    } else {
        // Fallback when we couldn't grab a direct terminal handle.
        let stdout = io::stdout();
        let mut lock = stdout.lock();
        lock.write_all(&out)?;
        lock.flush()?;
    }
    Ok(())
}

/// Queue the commands to (re)draw the bottom input line into `out`.
/// The real terminal cursor stays hidden the whole TUI lifetime; the
/// "visual cursor" is just an inverse-video character on the input row.
fn append_input_line<W: io::Write>(out: &mut W, app: &App) -> io::Result<()> {
    let w = app.cols;
    let rows = app.rows;

    queue!(out, MoveTo(0, rows - 2))?;

    let cursor_at_end = app.cursor >= app.input.len();
    let (before, at_char, after) = if cursor_at_end {
        (app.input.as_str(), " ", "")
    } else {
        let rest = &app.input[app.cursor..];
        let ch_len = rest.chars().next().map(|c| c.len_utf8()).unwrap_or(1);
        (&app.input[..app.cursor], &rest[..ch_len], &rest[ch_len..])
    };
    let input_vlen = if cursor_at_end {
        app.input.len() + 1
    } else {
        app.input.len()
    };
    let prompt = format!(
        "{DIM}│{RESET} {BLUE}{BOLD}bitaiir{RESET}{DIM}>{RESET} {before}{INV_ON}{at_char}{INV_OFF}{after}",
    );
    let padding = (w as usize).saturating_sub(input_vlen + 12);
    queue!(
        out,
        Print(&prompt),
        Print(" ".repeat(padding)),
        Print(format!("{DIM}│{RESET}")),
    )?;
    Ok(())
}

/// Redraw *only* the input line.  Used for pure input events (typing,
/// cursor moves, history navigation) — the rest of the screen hasn't
/// changed, so there's no reason to repaint the 5 KiB log frame.  A
/// ~200-byte write reaches the terminal in a single syscall and
/// renders atomically.
fn render_input_only(app: &mut App) -> io::Result<()> {
    let mut out: Vec<u8> = Vec::with_capacity(512);
    append_input_line(&mut out, app)?;

    if let Some(term) = app.term.as_mut() {
        term.write_all(&out)?;
        term.flush()?;
    } else {
        let stdout = io::stdout();
        let mut lock = stdout.lock();
        lock.write_all(&out)?;
        lock.flush()?;
    }
    Ok(())
}

/// Draw the autocomplete popup over the bottom of the log viewport.
fn render_autocomplete<W: io::Write>(out: &mut W, app: &App, log_bot: u16) -> io::Result<()> {
    let prefix = if app.input.starts_with('/') {
        &app.input[1..]
    } else {
        &app.input
    };
    let filtered = filter_commands(prefix);
    if filtered.is_empty() {
        return Ok(());
    }
    let max = app.viewport_height().min(10);
    let show = &filtered[..filtered.len().min(max)];
    let popup_h = show.len() as u16;
    let start_row = log_bot.saturating_sub(popup_h.saturating_sub(1));

    for (i, (name, desc)) in show.iter().enumerate() {
        let row = start_row + i as u16;
        if row > log_bot {
            break;
        }
        let marker = if i == app.autocomplete_idx {
            "▸"
        } else {
            " "
        };
        let bold = if i == app.autocomplete_idx { BOLD } else { "" };
        let content = format!(" {marker} {bold}{BLUE}/{name:<22}{RESET}  {DIM}{desc}{RESET}",);
        queue!(out, MoveTo(0, row))?;
        queue!(out, Print(bordered(&content, app.cols)))?;
    }
    Ok(())
}

// --- Selection & clipboard ---------------------------------------------- //

/// Materialize the current selection as plain text (ANSI stripped).
fn selection_text(app: &App) -> Option<String> {
    let (s, e) = app.selection.normalized()?;
    if !app.selection.active() {
        return None;
    }
    let mut out = String::new();
    for row in s.row..=e.row {
        if row >= app.buffer.lines.len() {
            break;
        }
        let line = &app.buffer.lines[row];
        let vlen = line_visible_len(line);
        let col_start = if row == s.row { s.col } else { 0 };
        let col_end = if row == e.row { e.col.min(vlen) } else { vlen };
        if col_start < col_end {
            let piece = slice_visible(line, col_start, col_end);
            out.push_str(&piece);
        }
        if row < e.row {
            out.push('\n');
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

fn copy_to_clipboard(app: &mut App, text: &str) {
    if let Some(cb) = app.clipboard.as_mut() {
        let _ = cb.set_text(text.to_owned());
    }
}

// --- Mouse handling ------------------------------------------------------ //

fn handle_mouse_down(col: u16, row: u16, app: &mut App) {
    if app.autocomplete {
        return;
    }
    let Some(p) = screen_to_buffer(col, row, app) else {
        return;
    };

    let now = Instant::now();
    let clicked_recently = app
        .last_click
        .map(|(lc, lr, lt)| {
            lc == col && lr == row && now.duration_since(lt).as_millis() <= MULTI_CLICK_MS
        })
        .unwrap_or(false);
    if clicked_recently {
        app.click_count += 1;
    } else {
        app.click_count = 1;
    }
    app.last_click = Some((col, row, now));

    match app.click_count {
        1 => {
            app.selection.clear();
            app.selection.anchor = Some(p);
            app.selection.focus = Some(p);
            app.selection.dragging = true;
            app.selection.mode = SelectionMode::Char;
        }
        2 => {
            // Word selection.
            if let Some(line) = app.buffer.lines.get(p.row) {
                let (s, e) = word_range(line, p.col);
                let sp = Point { row: p.row, col: s };
                let ep = Point { row: p.row, col: e };
                app.selection.anchor = Some(sp);
                app.selection.focus = Some(ep);
                app.selection.dragging = true;
                app.selection.mode = SelectionMode::Word;
                app.selection.anchor_span = Some((sp, ep));
            }
        }
        _ => {
            // Triple or more: whole line.
            if let Some(line) = app.buffer.lines.get(p.row) {
                let vlen = line_visible_len(line);
                let sp = Point { row: p.row, col: 0 };
                let ep = Point {
                    row: p.row,
                    col: vlen,
                };
                app.selection.anchor = Some(sp);
                app.selection.focus = Some(ep);
                app.selection.dragging = true;
                app.selection.mode = SelectionMode::Line;
                app.selection.anchor_span = Some((sp, ep));
            }
        }
    }
    app.mark_full();
}

fn handle_mouse_drag(col: u16, row: u16, app: &mut App) {
    if !app.selection.dragging {
        return;
    }
    // Clamp row to viewport; if outside, also scroll the view.
    let top = app.log_top();
    let bot = app.log_bottom();
    if row < top {
        app.buffer.scroll_up(1);
    } else if row > bot {
        app.buffer.scroll_down(1, app.viewport_height());
    }
    let clamped_row = row.clamp(top, bot);

    let Some(p) = screen_to_buffer(col, clamped_row, app) else {
        return;
    };

    match app.selection.mode {
        SelectionMode::Char => {
            app.selection.focus = Some(p);
        }
        SelectionMode::Word => {
            // Grow the selection away from the anchor span, aligning the
            // moving edge to word boundaries.
            let (a_start, a_end) = app.selection.anchor_span.unwrap_or_default();
            let word = app
                .buffer
                .lines
                .get(p.row)
                .map(|l| word_range(l, p.col))
                .unwrap_or((p.col, p.col));
            let new_point = Point {
                row: p.row,
                col: if p.before(&a_start) { word.0 } else { word.1 },
            };
            if p.before(&a_start) {
                app.selection.anchor = Some(a_end);
                app.selection.focus = Some(new_point);
            } else {
                app.selection.anchor = Some(a_start);
                app.selection.focus = Some(new_point);
            }
        }
        SelectionMode::Line => {
            let vlen = app
                .buffer
                .lines
                .get(p.row)
                .map(|l| line_visible_len(l))
                .unwrap_or(0);
            let (a_start, a_end) = app.selection.anchor_span.unwrap_or_default();
            if p.row < a_start.row {
                app.selection.anchor = Some(a_end);
                app.selection.focus = Some(Point { row: p.row, col: 0 });
            } else {
                app.selection.anchor = Some(a_start);
                app.selection.focus = Some(Point {
                    row: p.row,
                    col: vlen,
                });
            }
        }
    }
    app.mark_full();
}

fn handle_mouse_up(app: &mut App) {
    if !app.selection.dragging {
        return;
    }
    app.selection.dragging = false;
    if let Some(text) = selection_text(app) {
        let t = text.clone();
        copy_to_clipboard(app, &t);
    }
    app.mark_full();
}

// --- Main REPL ----------------------------------------------------------- //

pub fn run_repl(
    rpc_addr: &str,
    log_tx: std::sync::mpsc::Sender<String>,
    log_rx: Receiver<String>,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    let rt = tokio::runtime::Handle::current();
    let url = format!("http://{rpc_addr}");
    let client = jsonrpsee::http_client::HttpClientBuilder::default()
        .build(&url)
        .expect("build RPC client");

    let (cols, rows) = terminal::size()?;
    if rows < CHROME_ROWS + 2 {
        return Err(io::Error::other(
            "Terminal too small (need at least 6 rows)",
        ));
    }
    let mut app = App::new(cols, rows);

    // Enter the TUI: alternate screen, raw mode, mouse capture,
    // bracketed paste (so pasted text arrives as Event::Paste, not
    // as a flood of Char events typed into the input box).
    enable_raw_mode()?;
    execute!(
        io::stdout(),
        EnterAlternateScreen,
        EnableMouseCapture,
        EnableBracketedPaste,
        Hide,
    )?;

    // Banner — a single hint line explaining how to drive the TUI.
    app.push_log(format!(
        "{DIM}Mouse wheel to scroll · click-drag to select · Tab after / for commands · Ctrl+C to exit{RESET}"
    ));
    app.push_log(String::new());

    render_frame(&mut app)?;
    app.dirty = false;

    let outcome = (|| -> io::Result<()> {
        loop {
            // Exit if some other code path (e.g. async `/stop`) has
            // flipped the shutdown flag.
            if shutdown.load(Ordering::Relaxed) {
                return Ok(());
            }

            // Drain mining / system messages.
            while let Ok(msg) = log_rx.try_recv() {
                app.push_log(msg);
            }

            // Event poll (~20 fps).
            if event::poll(Duration::from_millis(50))? {
                match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => {
                        // Swallow key events injected by Windows
                        // Terminal's right-click "paste".  The WT
                        // paste bypasses bracketed-paste mode and
                        // arrives as raw Key events.  We suppress
                        // them after a right-click, EXTENDING the
                        // window every time a new char arrives so
                        // even a huge paste is fully swallowed.
                        if let Some(deadline) = app.suppress_keys_until {
                            if Instant::now() < deadline {
                                // More paste text arriving — keep
                                // the window open.
                                app.suppress_keys_until =
                                    Some(Instant::now() + Duration::from_millis(200));
                                continue;
                            }
                            app.suppress_keys_until = None;
                        }

                        // Any keypress clears an active selection.
                        if app.selection.active() {
                            app.selection.clear();
                            app.mark_full();
                        }
                        if handle_key(key, &mut app, &rt, &client, &log_tx, &shutdown)? {
                            return Ok(());
                        }
                    }

                    Event::Mouse(m) => match m.kind {
                        MouseEventKind::ScrollUp => {
                            app.buffer.scroll_up(WHEEL_STEP);
                            app.mark_full();
                        }
                        MouseEventKind::ScrollDown => {
                            app.buffer.scroll_down(WHEEL_STEP, app.viewport_height());
                            app.mark_full();
                        }
                        MouseEventKind::Down(MouseButton::Left) => {
                            handle_mouse_down(m.column, m.row, &mut app);
                        }
                        MouseEventKind::Drag(MouseButton::Left) => {
                            handle_mouse_drag(m.column, m.row, &mut app);
                        }
                        MouseEventKind::Up(MouseButton::Left) => {
                            handle_mouse_up(&mut app);
                        }
                        MouseEventKind::Down(MouseButton::Right) => {
                            // WT right-click = paste.  Suppress the
                            // incoming key-event burst for 500 ms.
                            app.suppress_keys_until =
                                Some(Instant::now() + Duration::from_millis(500));
                        }
                        _ => {}
                    },

                    Event::Resize(nc, nr) => {
                        app.cols = nc;
                        app.rows = nr;
                        let h = app.viewport_height();
                        if app.buffer.sticky {
                            app.buffer.scroll_to_bottom(h);
                        }
                        app.selection.clear();
                        app.mark_full();
                    }

                    // Ignore paste events — the user asked for
                    // no auto-paste into the input box.  Clipboard
                    // still works via explicit Ctrl-V in the future.
                    Event::Paste(_) => {}

                    _ => {}
                }
            }

            if app.dirty {
                if app.full_redraw {
                    render_frame(&mut app)?;
                    app.full_redraw = false;
                } else {
                    render_input_only(&mut app)?;
                }
                app.dirty = false;
            }
        }
    })();

    // Cleanup — always runs, even on error.
    shutdown.store(true, Ordering::Relaxed);
    let _ = execute!(
        io::stdout(),
        Show,
        DisableBracketedPaste,
        DisableMouseCapture,
        LeaveAlternateScreen,
    );
    let _ = disable_raw_mode();
    outcome
}

/// Process a key-press event.  Returns `Ok(true)` when the REPL should exit.
fn handle_key(
    key: crossterm::event::KeyEvent,
    app: &mut App,
    rt: &tokio::runtime::Handle,
    client: &jsonrpsee::http_client::HttpClient,
    log_tx: &std::sync::mpsc::Sender<String>,
    shutdown: &Arc<AtomicBool>,
) -> io::Result<bool> {
    match key.code {
        // --- Autocomplete ---------------------------------------------- //
        KeyCode::Tab if app.input.starts_with('/') => {
            let prefix = &app.input[1..];
            let filtered = filter_commands(prefix);
            if filtered.len() == 1 {
                app.set_input(format!("/{} ", filtered[0].0));
                app.autocomplete = false;
                app.mark_full();
            } else if !filtered.is_empty() {
                app.autocomplete = true;
                app.autocomplete_idx = 0;
                app.mark_full();
            }
        }
        KeyCode::Enter if app.autocomplete => {
            let prefix = if app.input.starts_with('/') {
                &app.input[1..]
            } else {
                &app.input
            };
            let filtered = filter_commands(prefix);
            if let Some((cmd, _)) = filtered.get(app.autocomplete_idx) {
                app.set_input(format!("/{cmd} "));
            }
            app.autocomplete = false;
            app.mark_full();
        }
        KeyCode::Up if app.autocomplete => {
            app.autocomplete_idx = app.autocomplete_idx.saturating_sub(1);
            app.mark_full();
        }
        KeyCode::Down if app.autocomplete => {
            let prefix = if app.input.starts_with('/') {
                &app.input[1..]
            } else {
                &app.input
            };
            let filtered = filter_commands(prefix);
            let max = filtered.len().min(10);
            if app.autocomplete_idx + 1 < max {
                app.autocomplete_idx += 1;
            }
            app.mark_full();
        }
        KeyCode::Esc if app.autocomplete => {
            app.autocomplete = false;
            app.clear_input();
            app.mark_full();
        }

        // --- Execute command ------------------------------------------ //
        KeyCode::Enter => {
            let raw = app.input.trim().to_string();
            app.clear_input();
            app.history_idx = None;
            app.autocomplete = false;

            if raw.is_empty() {
                // nothing
            } else if !raw.starts_with('/') {
                app.push_log(format!(
                    "  {DIM}Commands start with /. Type /help or Tab after /.{RESET}"
                ));
            } else {
                let cmd = raw[1..].trim().to_string();
                app.history.push(raw);
                app.push_log(format!("  {BLUE}> /{cmd}{RESET}"));

                if cmd == "exit" || cmd == "quit" {
                    app.push_log(format!("  {DIM}Goodbye.{RESET}"));
                    return Ok(true);
                }

                // Fire-and-forget: the RPC call runs as a tokio task,
                // the TUI keeps running, and the result lines arrive
                // via `log_tx` and show up in the next render pass.
                // /stop flips the shutdown flag synchronously so the
                // main loop exits on the next iteration.
                handle_command(rt, client, log_tx, &cmd, shutdown);
            }
        }

        // --- Scroll via keyboard -------------------------------------- //
        KeyCode::PageUp => {
            let h = app.viewport_height();
            app.buffer.scroll_up(h / 2);
            app.mark_full();
        }
        KeyCode::PageDown => {
            let h = app.viewport_height();
            app.buffer.scroll_down(h / 2, h);
            app.mark_full();
        }

        // --- Text editing -------------------------------------------- //
        KeyCode::Char(c) => {
            if key.modifiers.contains(KeyModifiers::CONTROL) && c == 'c' {
                return Ok(true);
            }
            app.insert_char(c);
            // Always re-evaluate autocomplete when input starts with /.
            // This way the popup re-opens as soon as matches exist,
            // even if it was previously closed by a no-match typo.
            if app.input.starts_with('/') {
                let prefix = &app.input[1..];
                if !filter_commands(prefix).is_empty() {
                    app.autocomplete = true;
                    app.autocomplete_idx = 0;
                } else {
                    app.autocomplete = false;
                }
                app.mark_full();
            } else if app.autocomplete {
                app.autocomplete = false;
                app.mark_full();
            }
        }
        KeyCode::Backspace => {
            app.delete_char();
            if app.input.starts_with('/') {
                let prefix = &app.input[1..];
                if !filter_commands(prefix).is_empty() {
                    app.autocomplete = true;
                    app.autocomplete_idx = 0;
                } else {
                    app.autocomplete = false;
                }
                app.mark_full();
            } else {
                if app.autocomplete {
                    app.autocomplete = false;
                    app.mark_full();
                }
            }
        }
        KeyCode::Left => {
            if app.cursor > 0 {
                let prev = app.input[..app.cursor]
                    .chars()
                    .last()
                    .map(|c| c.len_utf8())
                    .unwrap_or(0);
                app.cursor -= prev;
                app.dirty = true;
            }
        }
        KeyCode::Right => {
            if app.cursor < app.input.len() {
                let next = app.input[app.cursor..]
                    .chars()
                    .next()
                    .map(|c| c.len_utf8())
                    .unwrap_or(0);
                app.cursor += next;
                app.dirty = true;
            }
        }
        KeyCode::Home => {
            app.cursor = 0;
            app.dirty = true;
        }
        KeyCode::End => {
            app.cursor = app.input.len();
            app.dirty = true;
        }

        // --- Command history ----------------------------------------- //
        KeyCode::Up => {
            if !app.history.is_empty() {
                let idx = match app.history_idx {
                    Some(i) if i > 0 => i - 1,
                    Some(i) => i,
                    None => app.history.len() - 1,
                };
                app.history_idx = Some(idx);
                app.set_input(app.history[idx].clone());
            }
        }
        KeyCode::Down => {
            if let Some(idx) = app.history_idx {
                if idx + 1 < app.history.len() {
                    app.history_idx = Some(idx + 1);
                    app.set_input(app.history[idx + 1].clone());
                } else {
                    app.history_idx = None;
                    app.clear_input();
                }
            }
        }

        KeyCode::Esc => return Ok(true),
        _ => {}
    }
    Ok(false)
}

// --- Command handler ----------------------------------------------------- //

/// Dispatch a parsed command.
///
/// This function is **fire-and-forget**: it validates the command
/// synchronously, then spawns a Tokio task that runs the RPC call and
/// streams its output lines back through `log_tx`.  The TUI event loop
/// keeps running while the task works, so long-operations like
/// `sendtoaddress` (which mines ~2 s of anti-spam PoW) no longer
/// freeze the display.
fn handle_command(
    rt: &tokio::runtime::Handle,
    client: &jsonrpsee::http_client::HttpClient,
    log_tx: &std::sync::mpsc::Sender<String>,
    cmd: &str,
    shutdown: &Arc<AtomicBool>,
) {
    use jsonrpsee::core::client::ClientT;
    use jsonrpsee::rpc_params;

    // /help is synchronous — no RPC, just print the command table.
    if cmd == "help" {
        let _ = log_tx.send(format!("  {BOLD}Commands:{RESET}"));
        let _ = log_tx.send(String::new());
        for (name, desc) in COMMANDS {
            let _ = log_tx.send(format!("    {BLUE}/{name:<22}{RESET} {DIM}{desc}{RESET}"));
        }
        let _ = log_tx.send(String::new());
        return;
    }

    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.is_empty() {
        return;
    }
    let name = parts[0].to_string();

    // Cheap client-side validation — errors are reported synchronously
    // without hitting the RPC server.
    let validation_error: Option<String> = match name.as_str() {
        "getblock" if parts.len() < 2 => Some(format!("  {DIM}Usage: /getblock <height>{RESET}")),
        "getblock" if parts[1].parse::<u64>().is_err() => Some(format!(
            "  {RED}Error: '{}' is not a valid height.{RESET}",
            parts[1]
        )),
        "getbalance" if parts.len() < 2 => {
            Some(format!("  {DIM}Usage: /getbalance <address>{RESET}"))
        }
        "getbalance" if !is_valid_address(parts[1]) => Some(format!(
            "  {RED}Error: invalid BitAiir address (bad checksum or format).{RESET}"
        )),
        "gettransaction" if parts.len() < 2 => {
            Some(format!("  {DIM}Usage: /gettransaction <txid>{RESET}"))
        }
        "gettransactionhistory" if parts.len() < 2 => Some(format!(
            "  {DIM}Usage: /gettransactionhistory <address>{RESET}"
        )),
        "gettransactionhistory" if !is_valid_address(parts[1]) => Some(format!(
            "  {RED}Error: invalid BitAiir address (bad checksum or format).{RESET}"
        )),
        "sendtoaddress" if parts.len() < 3 => Some(format!(
            "  {DIM}Usage: /sendtoaddress <addr> <amount>{RESET}"
        )),
        "sendtoaddress" if !is_valid_address(parts[1]) => Some(format!(
            "  {RED}Error: invalid BitAiir address (bad checksum or format).{RESET}"
        )),
        "sendtoaddress" if parts[2].parse::<f64>().unwrap_or(0.0) <= 0.0 => {
            Some(format!("  {RED}Error: amount must be > 0.{RESET}"))
        }
        "encryptwallet" if parts.len() < 2 => {
            Some(format!("  {DIM}Usage: /encryptwallet <passphrase>{RESET}"))
        }
        "walletpassphrase" if parts.len() < 3 => Some(format!(
            "  {DIM}Usage: /walletpassphrase <passphrase> <timeout_seconds>{RESET}"
        )),
        "addpeer" if parts.len() < 2 || !parts[1].contains(':') => {
            Some(format!("  {DIM}Usage: /addpeer <ip:port>{RESET}"))
        }
        _ => None,
    };
    if let Some(err) = validation_error {
        let _ = log_tx.send(err);
        let _ = log_tx.send(String::new());
        return;
    }

    // /stop: flip the shutdown flag *before* spawning so the main loop
    // can exit even if the RPC response never arrives.
    if name == "stop" {
        shutdown.store(true, Ordering::Relaxed);
    }

    // Instant feedback for slow commands so the user doesn't think the
    // TUI froze.  The actual result appears when the async task finishes.
    match name.as_str() {
        "sendtoaddress" => {
            let _ = log_tx.send(format!(
                "  {DIM}Sending transaction (anti-spam PoW ~2s)...{RESET}"
            ));
        }
        "addpeer" => {
            let _ = log_tx.send(format!(
                "  {DIM}Connecting to peer (handshake + sync)...{RESET}"
            ));
        }
        _ => {}
    }

    // Snapshot everything the async task needs.
    let client = client.clone();
    let log_tx = log_tx.clone();
    let parts: Vec<String> = parts.into_iter().map(String::from).collect();

    rt.spawn(async move {
        let result: Result<serde_json::Value, _> = match name.as_str() {
            "getblockchaininfo" => client.request("getblockchaininfo", rpc_params![]).await,
            "getblock" => {
                let h: u64 = parts[1].parse().unwrap();
                client.request("getblock", rpc_params![h]).await
            }
            "getnewaddress" => client.request("getnewaddress", rpc_params![]).await,
            "getbalance" => {
                client
                    .request("getbalance", rpc_params![parts[1].clone()])
                    .await
            }
            "listaddresses" => client.request("listaddresses", rpc_params![]).await,
            "sendtoaddress" => {
                let amt: f64 = parts[2].parse().unwrap();
                client
                    .request("sendtoaddress", rpc_params![parts[1].clone(), amt])
                    .await
            }
            "getmempoolinfo" => client.request("getmempoolinfo", rpc_params![]).await,
            "gettransaction" => {
                client
                    .request("gettransaction", rpc_params![parts[1].clone()])
                    .await
            }
            "gettransactionhistory" => {
                client
                    .request("gettransactionhistory", rpc_params![parts[1].clone()])
                    .await
            }
            "mine-start" => client.request("setmining", rpc_params![true]).await,
            "mine-stop" => client.request("setmining", rpc_params![false]).await,
            "addpeer" => {
                client
                    .request("addpeer", rpc_params![parts[1].clone()])
                    .await
            }
            "listpeers" => client.request("listpeers", rpc_params![]).await,
            "listknownpeers" => client.request("listknownpeers", rpc_params![]).await,
            "encryptwallet" => {
                client
                    .request("encryptwallet", rpc_params![parts[1].clone()])
                    .await
            }
            "walletpassphrase" => {
                let timeout: u64 = parts[2].parse().unwrap_or(60);
                client
                    .request("walletpassphrase", rpc_params![parts[1].clone(), timeout])
                    .await
            }
            "walletlock" => client.request("walletlock", rpc_params![]).await,
            "stop" => client.request("stop", rpc_params![]).await,
            other => Ok(serde_json::json!(format!(
                "Unknown: '/{other}'. Type /help."
            ))),
        };

        match result {
            Ok(val) => {
                let json = serde_json::to_string_pretty(&val).unwrap_or_default();
                for line in json.lines() {
                    let _ = log_tx.send(format!("  {line}"));
                }
            }
            Err(e) => {
                let msg = e.to_string();
                let text = if let Some(start) = msg.find("message: \"") {
                    let rest = &msg[start + 10..];
                    if let Some(end) = rest.find('"') {
                        format!("  {RED}Error: {}{RESET}", &rest[..end])
                    } else {
                        format!("  {RED}Error: {msg}{RESET}")
                    }
                } else {
                    format!("  {RED}Error: {msg}{RESET}")
                };
                let _ = log_tx.send(text);
            }
        }
        let _ = log_tx.send(String::new());
    });
}
