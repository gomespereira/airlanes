use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{
        Axis, Bar, BarChart, BarGroup, Block, Borders, Cell, Chart, Dataset, GraphType, List,
        ListItem, Paragraph, Row, Table, TableState, Wrap,
    },
};

use crate::app::App;
use crate::model::{Band, ChannelScore, human_channel_label};

pub fn render(frame: &mut Frame, app: &App) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Min(12),
            Constraint::Length(9),
            Constraint::Length(3),
        ])
        .split(frame.area());

    render_header(frame, app, layout[0]);
    render_body(frame, app, layout[1]);
    render_recommendations(frame, app, layout[2]);
    render_footer(frame, app, layout[3]);
}

fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(32), Constraint::Length(24)])
        .split(area);

    let overview_lines = vec![
        Line::from(vec![
            Span::styled(
                "airlanes",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" WiFi channel scanner"),
        ]),
        Line::from(vec![
            Span::styled("Status: ", Style::default().fg(Color::Yellow)),
            Span::raw(&app.status),
        ]),
        Line::from(vec![
            Span::styled("Access: ", Style::default().fg(Color::Yellow)),
            Span::raw(
                app.access_status
                    .as_deref()
                    .unwrap_or("No macOS permission check needed."),
            ),
        ]),
    ];

    let overview = Paragraph::new(overview_lines)
        .block(Block::default().borders(Borders::ALL).title("Overview"))
        .wrap(Wrap { trim: true });
    frame.render_widget(overview, columns[0]);

    let count_panel = Paragraph::new(app.last_scan_summary.as_str())
        .block(Block::default().borders(Borders::ALL).title("Networks"))
        .style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(ratatui::layout::Alignment::Center)
        .wrap(Wrap { trim: true });
    frame.render_widget(count_panel, columns[1]);
}

fn render_body(frame: &mut Frame, app: &App, area: Rect) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .split(area);

    render_network_table(frame, app, columns[0]);
    render_congestion(frame, app, columns[1]);
}

fn render_network_table(frame: &mut Frame, app: &App, area: Rect) {
    let header =
        Row::new(["SSID", "Chan", "Signal", "Security"]).style(Style::default().fg(Color::Yellow));

    let rows = app.networks().iter().map(|network| {
        Row::new([
            Cell::from(network.ssid.clone()),
            Cell::from(network.channel.to_string()),
            Cell::from(format!(
                "{} dBm / {}%",
                network.signal_dbm,
                network.signal_percent()
            )),
            Cell::from(network.security.clone()),
        ])
    });

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(35),
            Constraint::Length(6),
            Constraint::Length(18),
            Constraint::Percentage(35),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Nearby Networks"),
    )
    .row_highlight_style(Style::default().bg(Color::DarkGray))
    .highlight_symbol(">> ");

    let mut state = TableState::default().with_selected(if app.networks().is_empty() {
        None
    } else {
        Some(app.selected_network)
    });
    frame.render_stateful_widget(table, area, &mut state);
}

fn render_congestion(frame: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    if let Some(analysis) = &app.analysis {
        render_bar_chart(
            frame,
            "2.4 GHz Congestion",
            &analysis.channels_24,
            rows[0],
            Color::Magenta,
        );
        render_bar_chart(
            frame,
            "5 GHz Congestion",
            &analysis.channels_5,
            rows[1],
            Color::Blue,
        );
    } else {
        let empty = Paragraph::new("Run a scan to populate congestion maps.")
            .block(Block::default().borders(Borders::ALL).title("Congestion"))
            .wrap(Wrap { trim: true });
        frame.render_widget(empty, area);
    }
}

fn render_bar_chart(
    frame: &mut Frame,
    title: &str,
    scores: &[ChannelScore],
    area: Rect,
    color: Color,
) {
    let bars = scores
        .iter()
        .map(|score| {
            let value = (score.congestion * 100.0).round().max(0.0) as u64;
            Bar::default()
                .label(human_channel_label(score.channel).into())
                .value(value)
                .text_value(format!("{value}"))
        })
        .collect::<Vec<_>>();

    let group = BarGroup::default().bars(&bars);
    let chart = BarChart::default()
        .block(Block::default().borders(Borders::ALL).title(title))
        .bar_width(5)
        .bar_gap(1)
        .value_style(Style::default().fg(Color::Black).bg(color))
        .label_style(Style::default().fg(Color::White))
        .data(group)
        .bar_style(Style::default().fg(color));

    frame.render_widget(chart, area);
}

fn render_recommendations(frame: &mut Frame, app: &App, area: Rect) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    if let Some(analysis) = &app.analysis {
        render_recommendation_panel(
            frame,
            columns[0],
            analysis.recommendation_24.band,
            analysis
                .recommendation_24
                .best_channel
                .as_ref()
                .map(|score| score.channel),
            &analysis.recommendation_24.explanation,
        );
        render_recommendation_panel(
            frame,
            columns[1],
            analysis.recommendation_5.band,
            analysis
                .recommendation_5
                .best_channel
                .as_ref()
                .map(|score| score.channel),
            &analysis.recommendation_5.explanation,
        );
    } else {
        let placeholder = Paragraph::new("Recommendations appear after the first successful scan.")
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Recommendations"),
            )
            .wrap(Wrap { trim: true });
        frame.render_widget(placeholder, area);
    }
}

fn render_recommendation_panel(
    frame: &mut Frame,
    area: Rect,
    band: Band,
    channel: Option<u16>,
    explanation: &str,
) {
    let heading = match channel {
        Some(channel) => format!("Recommended channel: {channel}\n\n"),
        None => String::new(),
    };
    let paragraph = Paragraph::new(format!("{heading}{explanation}"))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("Best {}", band.label())),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

#[allow(dead_code)]
fn _render_line_chart(
    frame: &mut Frame,
    title: &str,
    scores: &[ChannelScore],
    area: Rect,
    color: Color,
) {
    let points = scores
        .iter()
        .map(|score| (score.channel as f64, score.congestion as f64))
        .collect::<Vec<_>>();

    let x_labels = scores
        .iter()
        .step_by(scores.len().max(1) / 4 + 1)
        .map(|score| Span::raw(score.channel.to_string()))
        .collect::<Vec<_>>();

    let datasets = vec![
        Dataset::default()
            .name(title)
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(color))
            .data(&points),
    ];

    let chart = Chart::new(datasets)
        .block(Block::default().borders(Borders::ALL).title(title))
        .x_axis(
            Axis::default()
                .title("Channel")
                .bounds([
                    scores
                        .first()
                        .map(|score| score.channel as f64)
                        .unwrap_or(0.0),
                    scores
                        .last()
                        .map(|score| score.channel as f64)
                        .unwrap_or(1.0),
                ])
                .labels(x_labels),
        )
        .y_axis(Axis::default().title("Congestion").bounds([0.0, 3.0]));

    frame.render_widget(chart, area);
}

fn render_footer(frame: &mut Frame, _app: &App, area: Rect) {
    let controls = List::new(vec![ListItem::new(
        "Controls: q quit, r rescan, j/k or arrows move selection",
    )])
    .block(Block::default().borders(Borders::ALL).title("Keys"));
    frame.render_widget(controls, area);
}
