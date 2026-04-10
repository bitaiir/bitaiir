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

/// Application state for the TUI.
struct App {
    /// All log lines (mining events, system messages, command output).
    logs: Vec<String>,
    /// Current input buffer.
    input: String,
    /// Command history for scrolling with up/down arrows.
    history: Vec<String>,
    /// Current history index (-1 = typing new command).
    history_idx: Option<usize>,
    /// Whether to quit.
    should_quit: bool,
}

impl App {
    fn new() -> Self {
        Self {
            logs: vec![
                String::new(),
                "  Type 'help' for commands. Mining: 'mine start' / 'mine stop'".into(),
                String::new(),
            ],
            input: String::new(),
            history: Vec::new(),
            history_idx: None,
            should_quit: false,
        }
    }

    fn push_log(&mut self, line: String) {
        self.logs.push(line);
    }
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
                    KeyCode::Enter => {
                        let cmd = app.input.trim().to_string();
                        app.input.clear();
                        app.history_idx = None;

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
                        }
                    }
                    KeyCode::Backspace => {
                        app.input.pop();
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
                    KeyCode::Esc => {
                        app.should_quit = true;
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
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(5),    // log area
            Constraint::Length(3), // input bar
        ])
        .split(f.area());

    // --- Log area -------------------------------------------------------- //
    let log_lines: Vec<Line> = app
        .logs
        .iter()
        .map(|s| {
            if s.starts_with("  >") {
                // Command lines in cyan.
                Line::from(Span::styled(s.as_str(), Style::default().fg(Color::Cyan)))
            } else if s.contains("Block") || s.contains("mined") || s.contains("Mining") {
                // Mining events in green.
                Line::from(Span::styled(s.as_str(), Style::default().fg(Color::Green)))
            } else if s.contains("ERROR") || s.contains("Error") || s.contains("failed") {
                // Errors in red.
                Line::from(Span::styled(s.as_str(), Style::default().fg(Color::Red)))
            } else {
                Line::from(s.as_str())
            }
        })
        .collect();

    // Auto-scroll to bottom.
    let visible_height = chunks[0].height.saturating_sub(2) as usize; // -2 for borders
    let scroll = if log_lines.len() > visible_height {
        (log_lines.len() - visible_height) as u16
    } else {
        0
    };

    let log_panel = Paragraph::new(log_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" BitAiir Core v0.1.0 ")
                .title_style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
        )
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));

    f.render_widget(log_panel, chunks[0]);

    // --- Input bar ------------------------------------------------------- //
    let input_text = format!("bitaiir> {}", app.input);
    let input_bar = Paragraph::new(input_text.as_str())
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::White));

    f.render_widget(input_bar, chunks[1]);

    // Position the cursor inside the input bar.
    let cursor_x = chunks[1].x + 1 + "bitaiir> ".len() as u16 + app.input.len() as u16;
    let cursor_y = chunks[1].y + 1;
    f.set_cursor_position((cursor_x, cursor_y));
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
