//! Terminal UI for interactive mode.
//!
//! Split screen: scrollable log area on top, command input at the
//! bottom. Mining events, system logs, and command results all flow
//! into the log area. The input bar shows a `bitaiir>` prompt.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::time::Duration;

use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap,
};

/// Available slash commands with descriptions.
const COMMANDS: &[(&str, &str)] = &[
    ("getblockchaininfo", "Show chain status"),
    ("getblock", "Show block at height"),
    ("getnewaddress", "Generate a new address"),
    ("getbalance", "Show address balance"),
    ("listaddresses", "List all wallet addresses"),
    ("sendtoaddress", "Send AIIR to address"),
    ("getmempoolinfo", "Show mempool status"),
    ("mine-start", "Start mining"),
    ("mine-stop", "Stop mining"),
    ("addpeer", "Connect to a peer"),
    ("stop", "Stop the daemon"),
    ("help", "Show all commands"),
    ("exit", "Exit BitAiir"),
];

/// Application state for the TUI.
struct App {
    logs: Vec<String>,
    input: String,
    /// Cursor position within `input` (byte offset).
    cursor: usize,
    history: Vec<String>,
    history_idx: Option<usize>,
    should_quit: bool,
    autocomplete: bool,
    autocomplete_idx: usize,
    /// Manual scroll offset for the log panel. `None` = auto-scroll
    /// to bottom. `Some(n)` = user scrolled to line `n`.
    log_scroll: Option<u16>,
}

impl App {
    fn new() -> Self {
        Self {
            logs: vec![
                String::new(),
                "  Type / to see commands. Example: /mine-start".into(),
                String::new(),
            ],
            input: String::new(),
            cursor: 0,
            history: Vec::new(),
            history_idx: None,
            should_quit: false,
            autocomplete: false,
            autocomplete_idx: 0,
            log_scroll: None,
        }
    }

    fn push_log(&mut self, line: String) {
        self.logs.push(line);
        // Auto-scroll to bottom when new content arrives.
        self.log_scroll = None;
    }

    /// Insert a character at the cursor position.
    fn insert_char(&mut self, c: char) {
        self.input.insert(self.cursor, c);
        self.cursor += c.len_utf8();
    }

    /// Delete the character before the cursor.
    fn delete_char(&mut self) {
        if self.cursor > 0 {
            let prev = self.input[..self.cursor]
                .chars()
                .last()
                .map(|c| c.len_utf8())
                .unwrap_or(0);
            self.cursor -= prev;
            self.input.remove(self.cursor);
        }
    }

    /// Set the input and move cursor to the end.
    fn set_input(&mut self, s: String) {
        self.cursor = s.len();
        self.input = s;
    }

    /// Clear the input and reset cursor.
    fn clear_input(&mut self) {
        self.input.clear();
        self.cursor = 0;
    }
}

/// Filter commands matching the typed prefix.
fn filter_commands(prefix: &str) -> Vec<(&'static str, &'static str)> {
    COMMANDS
        .iter()
        .filter(|(name, _)| prefix.is_empty() || name.starts_with(prefix))
        .copied()
        .collect()
}

/// Run the TUI. Blocks until the user exits.
pub fn run_tui(
    rpc_addr: &str,
    log_rx: Receiver<String>,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<()> {
    let rt = tokio::runtime::Handle::current();
    let url = format!("http://{rpc_addr}");
    let client = HttpClientBuilder::default()
        .build(&url)
        .expect("build RPC client");

    // Setup terminal.
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();

    // Main loop.
    loop {
        // Drain mining/system log messages.
        while let Ok(msg) = log_rx.try_recv() {
            app.push_log(msg);
        }

        // Render.
        terminal.draw(|f| draw_ui(f, &app))?;

        if app.should_quit {
            break;
        }

        // Poll for keyboard events (50ms timeout = ~20 FPS).
        if event::poll(Duration::from_millis(50))? {
            let ev = event::read()?;

            // Mouse scroll support.
            if let Event::Mouse(mouse) = &ev {
                match mouse.kind {
                    MouseEventKind::ScrollUp => {
                        let current = app.log_scroll.unwrap_or(if app.logs.len() as u16 > 10 {
                            app.logs.len() as u16 - 10
                        } else {
                            0
                        });
                        app.log_scroll = Some(current.saturating_sub(3));
                    }
                    MouseEventKind::ScrollDown => {
                        if let Some(s) = app.log_scroll {
                            let new = s + 3;
                            let max = app.logs.len() as u16;
                            app.log_scroll = if new >= max { None } else { Some(new) };
                        }
                    }
                    _ => {}
                }
            }

            if let Event::Key(key) = ev {
                // On Windows, crossterm fires both Press and Release
                // events for each keystroke. Only process Press.
                if key.kind != crossterm::event::KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    // --- Autocomplete ------------------------------------ //
                    KeyCode::Enter if app.autocomplete => {
                        let prefix = if app.input.starts_with('/') {
                            &app.input[1..]
                        } else {
                            &app.input
                        };
                        let filtered = filter_commands(prefix);
                        if let Some((cmd, _)) = filtered.get(app.autocomplete_idx) {
                            app.set_input(format!("/{cmd}"));
                        }
                        app.autocomplete = false;
                    }
                    KeyCode::Tab if app.autocomplete => {
                        let prefix = if app.input.starts_with('/') {
                            &app.input[1..]
                        } else {
                            &app.input
                        };
                        let filtered = filter_commands(prefix);
                        if let Some((cmd, _)) = filtered.get(app.autocomplete_idx) {
                            app.set_input(format!("/{cmd}"));
                        }
                        app.autocomplete = false;
                    }
                    KeyCode::Up if app.autocomplete => {
                        app.autocomplete_idx = app.autocomplete_idx.saturating_sub(1);
                    }
                    KeyCode::Down if app.autocomplete => {
                        let prefix = if app.input.starts_with('/') {
                            &app.input[1..]
                        } else {
                            &app.input
                        };
                        let filtered = filter_commands(prefix);
                        if app.autocomplete_idx + 1 < filtered.len() {
                            app.autocomplete_idx += 1;
                        }
                    }

                    // --- Execute command --------------------------------- //
                    KeyCode::Enter => {
                        let raw = app.input.trim().to_string();
                        app.clear_input();
                        app.history_idx = None;
                        app.autocomplete = false;

                        if raw.is_empty() {
                            continue;
                        }

                        // Commands must start with "/".
                        if !raw.starts_with('/') {
                            app.push_log(format!("  > {raw}"));
                            app.push_log(
                                "  Commands must start with /. Type / to see available commands."
                                    .into(),
                            );
                            app.push_log(String::new());
                            continue;
                        }

                        let cmd = raw[1..].to_string(); // strip "/"
                        app.history.push(raw.clone()); // save WITH "/"
                        app.push_log(format!("  > /{cmd}"));

                        if cmd == "exit" || cmd == "quit" {
                            app.should_quit = true;
                            continue;
                        }

                        let output = handle_command(&rt, &client, &cmd, &shutdown);
                        for line in output.lines() {
                            app.push_log(format!("  {line}"));
                        }
                        app.push_log(String::new());

                        if cmd == "stop" {
                            app.should_quit = true;
                        }
                    }

                    // --- Text editing ------------------------------------ //
                    KeyCode::Char(c) => {
                        if key.modifiers.contains(KeyModifiers::CONTROL) && c == 'c' {
                            app.should_quit = true;
                        } else {
                            app.insert_char(c);
                            if app.input == "/" {
                                app.autocomplete = true;
                                app.autocomplete_idx = 0;
                            } else if app.autocomplete {
                                app.autocomplete_idx = 0;
                            }
                        }
                    }
                    KeyCode::Backspace => {
                        app.delete_char();
                        if app.input.is_empty() || !app.input.starts_with('/') {
                            app.autocomplete = false;
                        } else if app.autocomplete {
                            app.autocomplete_idx = 0;
                        }
                    }
                    KeyCode::Left => {
                        // Move cursor left by one character.
                        if app.cursor > 0 {
                            let prev = app.input[..app.cursor]
                                .chars()
                                .last()
                                .map(|c| c.len_utf8())
                                .unwrap_or(0);
                            app.cursor -= prev;
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
                        }
                    }
                    KeyCode::Home => {
                        app.cursor = 0;
                    }
                    KeyCode::End => {
                        app.cursor = app.input.len();
                    }

                    // --- Navigation -------------------------------------- //
                    KeyCode::Esc => {
                        if app.autocomplete {
                            app.autocomplete = false;
                            app.clear_input();
                        } else {
                            app.should_quit = true;
                        }
                        continue;
                    }
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
                    KeyCode::PageUp => {
                        // Scroll logs up.
                        let current = app.log_scroll.unwrap_or(0);
                        app.log_scroll = Some(current.saturating_sub(10));
                    }
                    KeyCode::PageDown => {
                        // Scroll logs down (None = auto-scroll to bottom).
                        if let Some(s) = app.log_scroll {
                            let new = s + 10;
                            let max = app.logs.len() as u16;
                            app.log_scroll = if new >= max { None } else { Some(new) };
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Restore terminal.
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

/// Draw the UI: log area (top) + input bar (bottom).
fn draw_ui(f: &mut ratatui::Frame, app: &App) {
    use ratatui::widgets::BorderType;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(5),    // log area
            Constraint::Length(3), // input bar
        ])
        .split(f.area());

    // --- Log area -------------------------------------------------------- //

    // Color palette built around the official BitAiir blue #1294D7.
    let dim = Style::default().fg(Color::DarkGray);
    let bitaiir_blue = Color::Rgb(18, 148, 215); // #1294D7 — brand color
    let accent = bitaiir_blue;
    let green = Color::Rgb(80, 200, 120);
    let red = Color::Rgb(240, 80, 80);
    let title_color = bitaiir_blue;

    let log_lines: Vec<Line> = app
        .logs
        .iter()
        .map(|s| {
            if s.starts_with("  >") {
                // User commands in accent blue.
                Line::from(Span::styled(s.as_str(), Style::default().fg(accent)))
            } else if s.contains("Height") && s.contains("Hash") {
                // Table header in dim.
                Line::from(Span::styled(s.as_str(), dim))
            } else if s.contains("---") && !s.contains('"') {
                // Separator lines in dim.
                Line::from(Span::styled(s.as_str(), dim))
            } else if s.contains("Block") || s.contains("mined") || s.contains("Mining") {
                // Mining events in green.
                Line::from(Span::styled(s.as_str(), Style::default().fg(green)))
            } else if s.contains("ERROR") || s.contains("Error") || s.contains("failed") {
                Line::from(Span::styled(s.as_str(), Style::default().fg(red)))
            } else if s.contains('"') || s.contains('{') || s.contains('}') {
                // JSON output in soft white.
                Line::from(Span::styled(s.as_str(), Style::default().fg(Color::White)))
            } else {
                Line::from(Span::styled(s.as_str(), Style::default().fg(Color::Gray)))
            }
        })
        .collect();

    // Scroll: use manual offset if set, otherwise auto-scroll to bottom.
    let visible_height = chunks[0].height.saturating_sub(2) as usize;
    let auto_scroll = if log_lines.len() > visible_height {
        (log_lines.len() - visible_height) as u16
    } else {
        0
    };
    let scroll = app.log_scroll.unwrap_or(auto_scroll);

    let log_panel = Paragraph::new(log_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(" BitAiir Core v0.1.0 ")
                .title_style(
                    Style::default()
                        .fg(title_color)
                        .add_modifier(Modifier::BOLD),
                ),
        )
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));

    f.render_widget(log_panel, chunks[0]);

    // --- Scrollbar ------------------------------------------------------- //
    if app.logs.len() > visible_height {
        let mut scrollbar_state = ScrollbarState::new(app.logs.len())
            .position(scroll as usize)
            .viewport_content_length(visible_height);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("▲"))
            .end_symbol(Some("▼"))
            .track_symbol(Some("│"))
            .thumb_symbol("█");
        f.render_stateful_widget(scrollbar, chunks[0], &mut scrollbar_state);
    }

    // --- Input bar ------------------------------------------------------- //

    // Styled prompt: "bitaiir" in accent, "> " dim, input in white.
    let input_line = Line::from(vec![
        Span::styled(
            " bitaiir",
            Style::default()
                .fg(title_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("> ", Style::default().fg(Color::DarkGray)),
        Span::styled(app.input.as_str(), Style::default().fg(Color::White)),
    ]);

    let input_bar = Paragraph::new(input_line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    f.render_widget(input_bar, chunks[1]);

    // Position the cursor at the correct position within the input.
    let prompt_len = " bitaiir> ".len() as u16;
    let cursor_x = chunks[1].x + 1 + prompt_len + app.cursor as u16;
    let cursor_y = chunks[1].y + 1;
    f.set_cursor_position((cursor_x, cursor_y));

    // --- Autocomplete popup ---------------------------------------------- //
    if app.autocomplete {
        let prefix = if app.input.starts_with('/') {
            &app.input[1..]
        } else {
            &app.input
        };
        let filtered = filter_commands(prefix);

        if !filtered.is_empty() {
            let popup_width: u16 = 55;
            let popup_height = (filtered.len() as u16 + 2).min(14);
            let inner_width = popup_width.saturating_sub(2) as usize; // minus borders
            let popup_area = ratatui::layout::Rect {
                x: chunks[1].x,
                y: chunks[1].y.saturating_sub(popup_height),
                width: popup_width,
                height: popup_height,
            };

            let accent = Color::Rgb(18, 148, 215); // #1294D7
            let items: Vec<Line> = filtered
                .iter()
                .enumerate()
                .map(|(i, (name, desc))| {
                    let (fg, bg) = if i == app.autocomplete_idx {
                        (Color::White, Color::Rgb(50, 50, 70))
                    } else {
                        (Color::Gray, Color::Rgb(20, 20, 30))
                    };
                    let text = format!(" /{:<22} {desc}", name);
                    let padded = format!("{:<width$}", text, width = inner_width);
                    let cmd_end = 24.min(padded.len());
                    let mut spans = Vec::new();
                    spans.push(Span::styled(
                        padded[..cmd_end].to_string(),
                        Style::default().fg(accent).bg(bg),
                    ));
                    if padded.len() > cmd_end {
                        spans.push(Span::styled(
                            padded[cmd_end..].to_string(),
                            Style::default().fg(fg).bg(bg),
                        ));
                    }
                    Line::from(spans)
                })
                .collect();

            let popup = Paragraph::new(items).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(ratatui::widgets::BorderType::Rounded)
                    .title(" Commands ")
                    .title_style(Style::default().fg(Color::Rgb(18, 148, 215)))
                    .border_style(Style::default().fg(Color::DarkGray)),
            );

            f.render_widget(ratatui::widgets::Clear, popup_area);
            f.render_widget(popup, popup_area);
        }
    }
}

/// Dispatch a command string to the RPC server and return the output.
fn handle_command(
    rt: &tokio::runtime::Handle,
    client: &HttpClient,
    cmd: &str,
    shutdown: &AtomicBool,
) -> String {
    if cmd == "help" {
        return [
            "Available commands:",
            "",
            "  /getblockchaininfo              Show chain status",
            "  /getblock <height>              Show block details",
            "  /getnewaddress                  Generate a new address",
            "  /getbalance <address>           Show address balance",
            "  /listaddresses                  List all wallet addresses",
            "  /sendtoaddress <address> <amt>  Send AIIR to an address",
            "  /getmempoolinfo                 Show mempool status",
            "  /mine-start                     Start mining",
            "  /mine-stop                      Stop mining",
            "  /addpeer <ip:port>              Connect to a peer node",
            "  /stop                           Stop the daemon",
            "  /help                           Show this help",
            "  /exit                           Exit (Esc also works)",
        ]
        .join("\n");
    }

    let parts: Vec<&str> = cmd.split_whitespace().collect();
    let name = parts[0];

    // --- Validate parameters before sending to RPC ----------------------- //

    match name {
        "getblock" => {
            if parts.len() < 2 {
                return "Usage: /getblock <height>\nExample: /getblock 0".into();
            }
            if parts[1].parse::<u64>().is_err() {
                return format!(
                    "Error: '{}' is not a valid block height. Use a number.",
                    parts[1]
                );
            }
        }
        "getbalance" => {
            if parts.len() < 2 {
                return "Usage: /getbalance <address>\nExample: /getbalance aiir1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH".into();
            }
            if !parts[1].starts_with("aiir") {
                return format!(
                    "Error: '{}' doesn't look like a BitAiir address (must start with 'aiir').",
                    parts[1]
                );
            }
        }
        "sendtoaddress" => {
            if parts.len() < 3 {
                return "Usage: /sendtoaddress <address> <amount>\nExample: /sendtoaddress aiir1BgG... 10.5".into();
            }
            if !parts[1].starts_with("aiir") {
                return format!("Error: '{}' doesn't look like a BitAiir address.", parts[1]);
            }
            match parts[2].parse::<f64>() {
                Err(_) => return format!("Error: '{}' is not a valid amount.", parts[2]),
                Ok(v) if v <= 0.0 => return "Error: amount must be greater than 0.".into(),
                _ => {}
            }
        }
        "mine-start" | "mine-stop" => {
            // No parameters needed.
        }
        "addpeer" => {
            if parts.len() < 2 {
                return "Usage: /addpeer <ip:port>\nExample: /addpeer 127.0.0.1:8444".into();
            }
            if !parts[1].contains(':') {
                return format!(
                    "Error: '{}' needs a port. Example: 127.0.0.1:8444",
                    parts[1]
                );
            }
        }
        _ => {}
    }

    // --- Dispatch to RPC ------------------------------------------------- //

    let result: Result<serde_json::Value, _> = rt.block_on(async {
        match name {
            "getblockchaininfo" => client.request("getblockchaininfo", rpc_params![]).await,
            "getblock" => {
                let h: u64 = parts[1].parse().unwrap();
                client.request("getblock", rpc_params![h]).await
            }
            "getnewaddress" => client.request("getnewaddress", rpc_params![]).await,
            "getbalance" => {
                client
                    .request("getbalance", rpc_params![parts[1].to_string()])
                    .await
            }
            "sendtoaddress" => {
                let amt: f64 = parts[2].parse().unwrap();
                client
                    .request("sendtoaddress", rpc_params![parts[1].to_string(), amt])
                    .await
            }
            "getmempoolinfo" => client.request("getmempoolinfo", rpc_params![]).await,
            "listaddresses" => client.request("listaddresses", rpc_params![]).await,
            "mine-start" => client.request("setmining", rpc_params![true]).await,
            "mine-stop" => client.request("setmining", rpc_params![false]).await,
            "addpeer" => {
                client
                    .request("addpeer", rpc_params![parts[1].to_string()])
                    .await
            }
            "stop" => {
                shutdown.store(true, Ordering::Relaxed);
                client.request("stop", rpc_params![]).await
            }
            _ => Ok(serde_json::json!(format!(
                "Unknown command: '{name}'. Type /help for available commands."
            ))),
        }
    });

    match result {
        Ok(val) => serde_json::to_string_pretty(&val).unwrap_or_default(),
        Err(e) => {
            let msg = e.to_string();
            // Clean up verbose jsonrpsee error format for friendlier output.
            if msg.contains("message:") {
                if let Some(start) = msg.find("message: \"") {
                    let rest = &msg[start + 10..];
                    if let Some(end) = rest.find('"') {
                        return format!("Error: {}", &rest[..end]);
                    }
                }
            }
            format!("Error: {msg}")
        }
    }
}
