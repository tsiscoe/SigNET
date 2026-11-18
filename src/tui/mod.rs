//! Ratatui v0.30+ interactive 3-pane `SigNET` Capability Firewall & Merkle Chain Inspector.

pub mod ui;

use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

use crate::ledger::{AuditReceipt, ToolPinRecord};

/// Active focus pane in the SigNET TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivePane {
    AuditFeed,
    ToolPins,
}

/// State model for the `SigNET` Ratatui dashboard.
pub struct SignetTuiApp {
    pub authority_pubkey_hex: String,
    pub chain_valid: bool,
    pub head_hash: String,
    pub receipts: Vec<AuditReceipt>,
    pub pins: Vec<ToolPinRecord>,
    pub selected_receipt: usize,
    pub selected_pin: usize,
    pub active_pane: ActivePane,
    pub should_quit: bool,
}

impl SignetTuiApp {
    pub fn new(
        authority_pubkey_hex: String,
        chain_valid: bool,
        head_hash: String,
        receipts: Vec<AuditReceipt>,
        pins: Vec<ToolPinRecord>,
    ) -> Self {
        Self {
            authority_pubkey_hex,
            chain_valid,
            head_hash,
            receipts,
            pins,
            selected_receipt: 0,
            selected_pin: 0,
            active_pane: ActivePane::AuditFeed,
            should_quit: false,
        }
    }

    pub fn toggle_pane(&mut self) {
        self.active_pane = match self.active_pane {
            ActivePane::AuditFeed => ActivePane::ToolPins,
            ActivePane::ToolPins => ActivePane::AuditFeed,
        };
    }

    pub fn move_down(&mut self) {
        match self.active_pane {
            ActivePane::AuditFeed => {
                if !self.receipts.is_empty() {
                    self.selected_receipt = (self.selected_receipt + 1) % self.receipts.len();
                }
            }
            ActivePane::ToolPins => {
                if !self.pins.is_empty() {
                    self.selected_pin = (self.selected_pin + 1) % self.pins.len();
                }
            }
        }
    }

    pub fn move_up(&mut self) {
        match self.active_pane {
            ActivePane::AuditFeed => {
                if !self.receipts.is_empty() {
                    if self.selected_receipt == 0 {
                        self.selected_receipt = self.receipts.len() - 1;
                    } else {
                        self.selected_receipt -= 1;
                    }
                }
            }
            ActivePane::ToolPins => {
                if !self.pins.is_empty() {
                    if self.selected_pin == 0 {
                        self.selected_pin = self.pins.len() - 1;
                    } else {
                        self.selected_pin -= 1;
                    }
                }
            }
        }
    }
}

pub fn run_interactive_tui(mut app: SignetTuiApp) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    res
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut SignetTuiApp,
) -> Result<()> {
    while !app.should_quit {
        terminal.draw(|frame| ui::render(frame, app))?;

        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    app.should_quit = true;
                }
                KeyCode::Tab => app.toggle_pane(),
                KeyCode::Down | KeyCode::Char('j') => app.move_down(),
                KeyCode::Up | KeyCode::Char('k') => app.move_up(),
                _ => {}
            }
        }
    }
    Ok(())
}
