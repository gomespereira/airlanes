mod app;
mod model;
mod scanner;
mod ui;

use std::io;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, prelude::CrosstermBackend};

use crate::app::App;
use crate::scanner::Scanner;

fn main() -> Result<()> {
    let scanner = Scanner::detect()?;
    let access_status = scanner.prepare()?;
    let initial_analysis = scanner.initial_snapshot()?;
    let mut app = App::new(scanner);
    app.set_access_status(access_status);
    app.set_initial_analysis(initial_analysis);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;
    app.request_scan();

    let tick_rate = Duration::from_millis(250);
    let mut last_tick = Instant::now();
    let run_result = run_app(&mut terminal, &mut app, tick_rate, &mut last_tick);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    run_result
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    tick_rate: Duration,
    last_tick: &mut Instant,
) -> Result<()> {
    loop {
        terminal.draw(|frame| ui::render(frame, app))?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                        KeyCode::Down | KeyCode::Char('j') => app.next_network(),
                        KeyCode::Up | KeyCode::Char('k') => app.previous_network(),
                        KeyCode::Char('r') => app.request_scan(),
                        _ => {}
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            app.on_tick();
            *last_tick = Instant::now();
        }
    }
}
