//! Terminal UI for interactive mode.
//!
//! Split screen: scrollable log area on top, command input at the
//! bottom. Mining events, system logs, and command results all flow
//! into the log area. The input bar shows a `bitaiir>` prompt.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
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
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

/// Available slash commands with descriptions.
const COMMANDS: &[(&str, &str)] = &[
    ("getblockchaininfo", "Show chain status"),
    ("getblock", "Show block at height"),
    ("getnewaddress", "Generate a new address"),
    ("getbalance", "Show address balance"),
    ("sendtoaddress", "Send AIIR to address"),
    ("getmempoolinfo", "Show mempool status"),
    ("mine start", "Start mining"),
    ("mine stop", "Stop mining"),
    ("addpeer", "Connect to a peer"),
    ("stop", "Stop the daemon"),
    ("help", "Show all commands"),
    ("exit", "Exit BitAiir"),
];

/// Application state for the TUI.
struct App {
    /// All log lines (mining events, system messages, command output).
    logs: Vec<String>,
    /// Current input buffer.
    input: String,
    /// Command history for scrolling with up/down arrows.
    history: Vec<String>,
    /// Current history index.
    history_idx: Option<usize>,
    /// Whether to quit.
    should_quit: bool,
    /// Autocomplete popup visible.
    autocomplete: bool,
    /// Selected index in the autocomplete popup.
    autocomplete_idx: usize,
}

impl App {
    fn new() -> Self {
        Self {
            logs: vec![
                String::new(),
                "  Type /command or 'help'. Mining: /mine start".into(),
                String::new(),
            ],
            input: String::new(),
            history: Vec::new(),
            history_idx: None,
            should_quit: false,
            autocomplete: false,
            autocomplete_idx: 0,
        }
    }

    fn push_log(&mut self, line: String) {
        self.logs.push(line);
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
    execute!(stdout, EnterAlternateScreen)?;
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
            if let Event::Key(key) = event::read()? {
                // On Windows, crossterm fires both Press and Release
                // events for each keystroke. Only process Press.
                if key.kind != crossterm::event::KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Enter if app.autocomplete => {
                        // Accept the selected autocomplete entry.
                        let prefix = if app.input.starts_with('/') {
                            &app.input[1..]
                        } else {
                            &app.input
                        };
                        let filtered = filter_commands(prefix);
                        if let Some((cmd, _)) = filtered.get(app.autocomplete_idx) {
                            app.input = format!("/{cmd}");
                        }
                        app.autocomplete = false;
                        // Don't execute yet — let user add args or press Enter again.
                    }
                    KeyCode::Enter => {
                        // Strip leading "/" if present.
                        let cmd = app.input.trim().trim_start_matches('/').to_string();
                        app.input.clear();
                        app.history_idx = None;
                        app.autocomplete = false;

                        if cmd.is_empty() {
                            continue;
                        }

                        app.history.push(cmd.clone());
                        app.push_log(format!("  > {cmd}"));

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
                    KeyCode::Char(c) => {
                        if key.modifiers.contains(KeyModifiers::CONTROL) && c == 'c' {
                            app.should_quit = true;
                        } else {
                            app.input.push(c);
                            // Trigger autocomplete when "/" is the first character.
                            if app.input == "/" {
                                app.autocomplete = true;
                                app.autocomplete_idx = 0;
                            } else if app.autocomplete {
                                // Update filter, reset selection.
                                app.autocomplete_idx = 0;
                            }
                        }
                    }
                    KeyCode::Backspace => {
                        app.input.pop();
                        if app.input.is_empty() || !app.input.starts_with('/') {
                            app.autocomplete = false;
                        } else if app.autocomplete {
                            app.autocomplete_idx = 0;
                        }
                    }
                    KeyCode::Esc => {
                        if app.autocomplete {
                            app.autocomplete = false;
                            app.input.clear();
                        } else {
                            app.should_quit = true;
                        }
                        continue;
                    }
                    KeyCode::Tab if app.autocomplete => {
                        // Tab also accepts the selection (like shell completion).
                        let prefix = if app.input.starts_with('/') {
                            &app.input[1..]
                        } else {
                            &app.input
                        };
                        let filtered = filter_commands(prefix);
                        if let Some((cmd, _)) = filtered.get(app.autocomplete_idx) {
                            app.input = format!("/{cmd}");
                        }
                        app.autocomplete = false;
                    }
                    KeyCode::Up if app.autocomplete => {
                        if app.autocomplete_idx > 0 {
                            app.autocomplete_idx -= 1;
                        }
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
                    KeyCode::Up => {
                        // Scroll through command history.
                        if !app.history.is_empty() {
                            let idx = match app.history_idx {
                                Some(i) if i > 0 => i - 1,
                                Some(i) => i,
                                None => app.history.len() - 1,
                            };
                            app.history_idx = Some(idx);
                            app.input = app.history[idx].clone();
                        }
                    }
                    KeyCode::Down => {
                        if let Some(idx) = app.history_idx {
                            if idx + 1 < app.history.len() {
                                app.history_idx = Some(idx + 1);
                                app.input = app.history[idx + 1].clone();
                            } else {
                                app.history_idx = None;
                                app.input.clear();
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Restore terminal.
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
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
    let yellow = Color::Rgb(255, 200, 60);

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

    // Auto-scroll to bottom.
    let visible_height = chunks[0].height.saturating_sub(2) as usize;
    let scroll = if log_lines.len() > visible_height {
        (log_lines.len() - visible_height) as u16
    } else {
        0
    };

    let log_panel = Paragraph::new(log_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(" BitAiir Core v0.1.0 ")
                .title_style(Style::default().fg(yellow).add_modifier(Modifier::BOLD)),
        )
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));

    f.render_widget(log_panel, chunks[0]);

    // --- Input bar ------------------------------------------------------- //

    // Styled prompt: "bitaiir" in accent, "> " dim, input in white.
    let input_line = Line::from(vec![
        Span::styled(
            " bitaiir",
            Style::default().fg(yellow).add_modifier(Modifier::BOLD),
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

    // Position the cursor after the prompt + input text.
    let prompt_len = " bitaiir> ".len() as u16;
    let cursor_x = chunks[1].x + 1 + prompt_len + app.input.len() as u16;
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
                    .title_style(Style::default().fg(Color::Rgb(255, 200, 60)))
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
            "  getblockchaininfo              Show chain status",
            "  getblock <height>              Show block details",
            "  getnewaddress                  Generate a new address",
            "  getbalance <address>           Show address balance",
            "  sendtoaddress <address> <amt>  Send AIIR",
            "  getmempoolinfo                 Show mempool status",
            "  mine start                     Start mining",
            "  mine stop                      Stop mining",
            "  addpeer <ip:port>              Connect to a peer",
            "  stop                           Stop the daemon",
            "  help                           Show this help",
            "  exit / quit / Esc              Exit",
        ]
        .join("\n");
    }

    let parts: Vec<&str> = cmd.split_whitespace().collect();
    let name = parts[0];

    let result: Result<serde_json::Value, _> = rt.block_on(async {
        match name {
            "getblockchaininfo" => client.request("getblockchaininfo", rpc_params![]).await,
            "getblock" => {
                let h: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                client.request("getblock", rpc_params![h]).await
            }
            "getnewaddress" => client.request("getnewaddress", rpc_params![]).await,
            "getbalance" => {
                let a = parts.get(1).copied().unwrap_or("");
                client
                    .request("getbalance", rpc_params![a.to_string()])
                    .await
            }
            "sendtoaddress" => {
                let a = parts.get(1).copied().unwrap_or("");
                let amt: f64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0.0);
                client
                    .request("sendtoaddress", rpc_params![a.to_string(), amt])
                    .await
            }
            "getmempoolinfo" => client.request("getmempoolinfo", rpc_params![]).await,
            "mine" => {
                let action = parts.get(1).copied().unwrap_or("status");
                match action {
                    "start" => client.request("setmining", rpc_params![true]).await,
                    "stop" => client.request("setmining", rpc_params![false]).await,
                    _ => Ok(serde_json::json!("Usage: mine start | mine stop")),
                }
            }
            "addpeer" => {
                let a = parts.get(1).copied().unwrap_or("");
                client.request("addpeer", rpc_params![a.to_string()]).await
            }
            "stop" => {
                shutdown.store(true, Ordering::Relaxed);
                client.request("stop", rpc_params![]).await
            }
            _ => Ok(serde_json::json!(format!(
                "Unknown command: '{name}'. Type 'help'."
            ))),
        }
    });

    match result {
        Ok(val) => serde_json::to_string_pretty(&val).unwrap_or_default(),
        Err(e) => format!("Error: {e}"),
    }
}
