//! Ratatui v0.30+ layout and ANSI/OSC escape-sanitized renderer (`CWE-150`) for **SigNET**.

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

use crate::tui::{ActivePane, SignetTuiApp};

/// Strip C0/C1 control characters and ANSI/OSC escape sequences (`\x1b`) before rendering
/// untrusted tool names, arguments, or reasons into the terminal buffer (`CWE-150`).
pub fn sanitize_terminal_str(input: &str) -> String {
    input
        .chars()
        .filter(|&c| c == '\n' || c == '\t' || (!c.is_control() && c != '\u{001b}'))
        .collect()
}

pub fn render(frame: &mut Frame, app: &SignetTuiApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(4),
            Constraint::Percentage(58),
            Constraint::Percentage(32),
            Constraint::Length(2),
        ])
        .split(frame.area());

    // 1. Masthead Banner (SigNET with bold NET)
    let chain_badge = if app.chain_valid {
        Span::styled(
            " MERKLE CHAIN: VERIFIED ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            " MERKLE CHAIN: TAMPERED ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        )
    };

    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " Sig",
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::ITALIC),
        ),
        Span::styled(
            "NET v0.4.0 ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" // "),
        Span::styled(
            "CRYPTOGRAPHIC MCP & AGENT CAPABILITY FIREWALL  ",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        chain_badge,
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    // 2. Cryptographic Authority Telemetry Strip
    let meta_text = format!(
        "Ed25519 Authority PubKey: {}   |   Receipts: {}   |   Pinned Tools: {}\nBLAKE3 Chain Head: {}",
        sanitize_terminal_str(&app.authority_pubkey_hex),
        app.receipts.len(),
        app.pins.len(),
        sanitize_terminal_str(&app.head_hash)
    );
    let meta_pane = Paragraph::new(meta_text).block(
        Block::default()
            .title(" [00] AUTHORITY & MERKLE TELEMETRY ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(meta_pane, chunks[1]);

    // 3. Append-Only BLAKE3 Merkle Audit Log Table
    let audit_border = if app.active_pane == ActivePane::AuditFeed {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let audit_header = Row::new(
        [
            "SEQ",
            "DECISION",
            "SUBJECT",
            "TOOL",
            "ENTRY BLAKE3",
            "REASON",
        ]
        .iter()
        .map(|h| {
            Cell::from(*h).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
        }),
    )
    .height(1);

    let audit_rows = app.receipts.iter().enumerate().map(|(idx, r)| {
        let dec_style = if r.decision == "ALLOW" {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        };
        let row_style = if idx == app.selected_receipt {
            Style::default().bg(Color::DarkGray)
        } else {
            Style::default()
        };
        let short_hash: String = r.entry_hash.chars().take(16).collect();
        Row::new(vec![
            Cell::from(r.seq.to_string()),
            Cell::from(sanitize_terminal_str(&r.decision)).style(dec_style),
            Cell::from(sanitize_terminal_str(&r.subject)),
            Cell::from(sanitize_terminal_str(&r.tool_name)),
            Cell::from(sanitize_terminal_str(&short_hash)),
            Cell::from(sanitize_terminal_str(&r.reason)),
        ])
        .style(row_style)
    });

    let audit_table = Table::new(
        audit_rows,
        [
            Constraint::Length(6),
            Constraint::Length(10),
            Constraint::Length(18),
            Constraint::Length(18),
            Constraint::Length(18),
            Constraint::Percentage(40),
        ],
    )
    .header(audit_header)
    .block(
        Block::default()
            .title(" [01] APPEND-ONLY BLAKE3 MERKLE AUDIT LOG (ED25519 SIGNED) ")
            .borders(Borders::ALL)
            .border_style(audit_border),
    );
    frame.render_widget(audit_table, chunks[2]);

    // 4. Anti-Rug-Pull Tool Schema Pins Table
    let pin_border = if app.active_pane == ActivePane::ToolPins {
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let pin_header = Row::new(
        ["MCP SERVER", "TOOL NAME", "SCHEMA BLAKE3 PIN", "PINNED AT"]
            .iter()
            .map(|h| {
                Cell::from(*h).style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )
            }),
    )
    .height(1);

    let pin_rows = app.pins.iter().enumerate().map(|(idx, p)| {
        let style = if idx == app.selected_pin {
            Style::default().bg(Color::DarkGray)
        } else {
            Style::default()
        };
        Row::new(vec![
            Cell::from(sanitize_terminal_str(&p.server_name)),
            Cell::from(sanitize_terminal_str(&p.tool_name)),
            Cell::from(sanitize_terminal_str(&p.schema_blake3)),
            Cell::from(sanitize_terminal_str(&p.pinned_at)),
        ])
        .style(style)
    });

    let pin_table = Table::new(
        pin_rows,
        [
            Constraint::Length(20),
            Constraint::Length(22),
            Constraint::Percentage(40),
            Constraint::Percentage(25),
        ],
    )
    .header(pin_header)
    .block(
        Block::default()
            .title(" [02] ANTI-RUG-PULL MCP TOOL SCHEMA PINS (BLAKE3) ")
            .borders(Borders::ALL)
            .border_style(pin_border),
    );
    frame.render_widget(pin_table, chunks[3]);

    // 5. Footer Bar
    let footer =
        Paragraph::new(" [Tab] Switch Pane   [j/k] Navigate   [q / Esc] Quit SigNET Inspector")
            .style(Style::default().fg(Color::Gray));
    frame.render_widget(footer, chunks[4]);
}
