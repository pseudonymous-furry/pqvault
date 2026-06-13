// THIS IS A PRE-RELEASE STILL. DO NOT USE THIS IN PRODUCTION! -w-

use std::io;

use anyhow::{anyhow, Context, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent},
    terminal,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame, Terminal,
};

use crate::models::{Entry, UserIndex, UserRecord, Vault};
use crate::util::printable_password;

#[derive(Debug, Clone, Copy)]
pub enum LoginSelection {
    Existing(usize),
    CreateNew,
    DeleteUser,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Title,
    Username,
    Password,
    GenPassword,
    ShowPassword,
    Notes,
    Save,
    Cancel,
}

#[derive(Debug, Clone, Copy)]
enum EditorTarget {
    New,
    Existing(usize),
}

#[derive(Debug, Clone)]
struct EditorState {
    target: EditorTarget,
    draft: Entry,
    focus: Focus,
    show_pass: bool,
}

enum UiMode {
    Browse,
    Viewing(usize),
    Editing(EditorState),
    ConfirmDelete(usize),
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    terminal::enable_raw_mode().context("enable raw mode")?;
    let mut stdout = io::stdout();
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)?;
    Ok(Terminal::new(CrosstermBackend::new(stdout))?)
}

fn restore_terminal(term: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    terminal::disable_raw_mode().ok();
    crossterm::execute!(term.backend_mut(), crossterm::terminal::LeaveAlternateScreen).ok();
    Ok(())
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn mask_password(password: &str) -> String {
    "*".repeat(password.chars().count())
}

fn next_focus(f: Focus) -> Focus {
    use Focus::*;
    match f {
        Title => Username,
        Username => Password,
        Password => ShowPassword,
        ShowPassword => GenPassword,
        GenPassword => Notes,
        Notes => Save,
        Save => Cancel,
        Cancel => Title,
    }
}

fn prev_focus(f: Focus) -> Focus {
    use Focus::*;
    match f {
        Title => Cancel,
        Username => Title,
        Password => Username,
        ShowPassword => Password,
        GenPassword => ShowPassword,
        Notes => GenPassword,
        Save => Notes,
        Cancel => Save,
    }
}

pub fn tui_login_select(index: &UserIndex) -> Result<LoginSelection> {
    let mut term = setup_terminal()?;
    let mut selected = 0usize;

    let res = (|| -> Result<LoginSelection> {
        loop {
            term.draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(2)
                    .constraints([
                        Constraint::Length(3),
                        Constraint::Min(5),
                        Constraint::Length(2),
                    ])
                    .split(f.area());

                let header = Paragraph::new("Vault Login")
                    .alignment(Alignment::Center)
                    .block(Block::default().borders(Borders::ALL).title("pqvault"));
                f.render_widget(header, chunks[0]);

                let mut items: Vec<ListItem> = index
                    .users
                    .iter()
                    .map(|u| ListItem::new(u.username.clone()))
                    .collect();
                items.push(ListItem::new("[Create new]"));
                items.push(ListItem::new("[Delete user]"));

                let mut state = ListState::default();
                if !items.is_empty() {
                    state.select(Some(selected.min(items.len().saturating_sub(1))));
                }

                let list = List::new(items)
                    .block(Block::default().borders(Borders::ALL).title("users"))
                    .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

                f.render_stateful_widget(list, chunks[1], &mut state);

                let help = Paragraph::new("↑↓ select | Enter open | q quit")
                    .alignment(Alignment::Center)
                    .block(Block::default().borders(Borders::ALL));
                f.render_widget(help, chunks[2]);
            })?;

            if let Event::Key(KeyEvent { code, .. }) = event::read()? {
                match code {
                    KeyCode::Char('q') => return Err(anyhow!("quit")),
                    KeyCode::Up => selected = selected.saturating_sub(1),
                    KeyCode::Down => {
                        if selected + 1 < index.users.len() + 2 {
                            selected += 1;
                        }
                    }
                    KeyCode::Enter => {
                        return Ok(
                            if selected < index.users.len() {
                                LoginSelection::Existing(selected)
                            } else if selected == index.users.len() {
                                LoginSelection::CreateNew
                            } else {
                                LoginSelection::DeleteUser
                            }
                        );
                    }
                    _ => {}
                }
            }
        }
    })();

    restore_terminal(&mut term)?;
    res
}

pub fn tui_run_vault(
    user: &UserRecord,
    vault: &mut Vault,
    _keys: &crate::crypto::UserKeys,
) -> Result<()> {
    let mut term = setup_terminal()?;
    let mut selected = 0usize;
    let mut dirty = false;
    let mut mode = UiMode::Browse;

    let res = (|| -> Result<()> {
        loop {
            term.draw(|f| match &mode {
                UiMode::Browse => draw_browse(f, user, vault, selected, dirty),
                UiMode::Viewing(i) => {
                    draw_browse(f, user, vault, selected, dirty);
                    draw_entry_view(f, vault.entries.get(*i));
                }
                UiMode::Editing(state) => {
                    draw_browse(f, user, vault, selected, dirty);
                    draw_editor(f, state);
                }
                UiMode::ConfirmDelete(target) => {
                    draw_browse(f, user, vault, selected, dirty);
                    draw_delete_confirm(f, vault.entries.get(*target));
                }
            })?;

            if let Event::Key(KeyEvent { code, .. }) = event::read()? {
                match &mut mode {
                    UiMode::Browse => match code {
                        KeyCode::Char('q') | KeyCode::Char('l') => break,

                        KeyCode::Up => selected = selected.saturating_sub(1),

                        KeyCode::Down => {
                            if selected + 1 < vault.entries.len() {
                                selected += 1;
                            }
                        }

                        KeyCode::Enter => {
                            if !vault.entries.is_empty() && selected < vault.entries.len() {
                                mode = UiMode::Viewing(selected);
                            }
                        }

                        KeyCode::Char('e') => {
                            if let Some(entry) = vault.entries.get(selected).cloned() {
                                mode = UiMode::Editing(EditorState {
                                    target: EditorTarget::Existing(selected),
                                    draft: entry,
                                    focus: Focus::Title,
                                    show_pass: false,
                                });
                            }
                        }

                        KeyCode::Char('a') => {
                            mode = UiMode::Editing(EditorState {
                                target: EditorTarget::New,
                                draft: Entry::empty(),
                                focus: Focus::Title,
                                show_pass: false,
                            });
                        }

                        KeyCode::Char('g') => {
                            let mut draft = Entry::empty();
                            draft.password = printable_password(32);
                            mode = UiMode::Editing(EditorState {
                                target: EditorTarget::New,
                                draft,
                                focus: Focus::Title,
                                show_pass: false,
                            });
                        }

                        KeyCode::Char('D') => {
                            if !vault.entries.is_empty() {
                                mode = UiMode::ConfirmDelete(selected);
                            }
                        }

                        _ => {}
                    },

                    UiMode::Viewing(_) => {
                        mode = UiMode::Browse;
                    }

                    UiMode::Editing(state) => {
                        if let Some(save) = handle_editor(state, code) {
                            if save {
                                match state.target {
                                    EditorTarget::New => {
                                        vault.entries.push(state.draft.clone());
                                        selected = vault.entries.len().saturating_sub(1);
                                    }
                                    EditorTarget::Existing(i) => {
                                        if i < vault.entries.len() {
                                            vault.entries[i] = state.draft.clone();
                                            selected = i;
                                        }
                                    }
                                }
                                dirty = true;
                            }
                            mode = UiMode::Browse;
                        }
                    }

                    UiMode::ConfirmDelete(target) => match code {
                        KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                            if *target < vault.entries.len() {
                                vault.entries.remove(*target);
                                selected = selected.min(vault.entries.len().saturating_sub(1));
                                dirty = true;
                            }
                            mode = UiMode::Browse;
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                            mode = UiMode::Browse;
                        }
                        _ => {}
                    },
                }
            }
        }
        Ok(())
    })();

    restore_terminal(&mut term)?;
    res
}

fn handle_editor(state: &mut EditorState, key: KeyCode) -> Option<bool> {
    match key {
        KeyCode::Esc => return Some(false),

        KeyCode::Tab | KeyCode::Down => {
            state.focus = next_focus(state.focus);
        }

        KeyCode::Up => {
            state.focus = prev_focus(state.focus);
        }

        KeyCode::Enter => match state.focus {
            Focus::Title | Focus::Username | Focus::Password => {
                state.focus = next_focus(state.focus);
            }
            Focus::Notes => state.draft.notes.push('\n'),
            Focus::Save => return Some(true),
            Focus::Cancel => return Some(false),
            Focus::ShowPassword => {
                state.show_pass = !state.show_pass;
            }
            Focus::GenPassword => {
                state.draft.password = printable_password(32);
            }
        },

        KeyCode::Backspace => match state.focus {
            Focus::Title => {
                state.draft.title.pop();
            }
            Focus::Username => {
                state.draft.username.pop();
            }
            Focus::Password => {
                state.draft.password.pop();
            }
            Focus::Notes => {
                state.draft.notes.pop();
            }
            _ => {}
        },

        KeyCode::Char(c) => match state.focus {
            Focus::Title => state.draft.title.push(c),
            Focus::Username => state.draft.username.push(c),
            Focus::Password => state.draft.password.push(c),
            Focus::Notes => state.draft.notes.push(c),
            _ => {}
        },
        _ => {}
    }

    None
}

fn draw_browse(f: &mut Frame<'_>, user: &UserRecord, vault: &Vault, selected: usize, dirty: bool) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(12),
            Constraint::Length(3),
        ])
        .split(f.area());

    let header = Paragraph::new(format!(
        "user: {}   vault: {}   state: {}",
        user.username,
        user.vault_path,
        if dirty { "modified" } else { "clean" }
    ))
    .block(Block::default().borders(Borders::ALL).title("pqvault"));

    f.render_widget(header, outer[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(outer[1]);

    let mut state = ListState::default();
    if !vault.entries.is_empty() {
        state.select(Some(selected.min(vault.entries.len().saturating_sub(1))));
    }

    let entry_items: Vec<ListItem> = if vault.entries.is_empty() {
        vec![ListItem::new("No entries yet. Press 'a' to add one.")]
    } else {
        vault
            .entries
            .iter()
            .map(|e| {
                let title = if e.title.trim().is_empty() {
                    "(untitled)"
                } else {
                    e.title.as_str()
                };
                ListItem::new(title.to_string())
            })
            .collect()
    };

    let list = List::new(entry_items)
        .block(Block::default().borders(Borders::ALL).title("entries"))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_stateful_widget(list, body[0], &mut state);

    let info_text = if let Some(entry) = vault.entries.get(selected) {
        let title = if entry.title.trim().is_empty() {
            "(untitled)"
        } else {
            entry.title.as_str()
        };

        format!(
            "Selected: {}\n\nEnter: view full entry\nE: edit\nD: delete",
            title
        )
    } else {
        "No entry selected.\n\nEnter: view full entry\nE: edit\nD: delete".to_string()
    };

    let info = Paragraph::new(info_text)
        .wrap(Wrap { trim: false })
        .block(Block::default().borders(Borders::ALL).title("browse"));

    f.render_widget(info, body[1]);

    let help = Paragraph::new("↑↓ move | Enter view | e edit | a add | g generate | D delete | q quit")
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(help, outer[2]);
}

fn draw_entry_view(f: &mut Frame<'_>, entry: Option<&Entry>) {
    let area = centered_rect(80, 72, f.area());
    f.render_widget(Clear, area);

    let text = entry
        .map(|e| {
            format!(
                "Title: {}\n\nUsername: {}\n\nPassword: {}\n\nNotes:\n{}\n\nPress any key to return.",
                e.title,
                e.username,
                e.password,
                e.notes
            )
        })
        .unwrap_or_else(|| "No entry selected.\n\nPress any key to return.".to_string());

    let p = Paragraph::new(text)
        .wrap(Wrap { trim: false })
        .block(Block::default().borders(Borders::ALL).title("entry view"));

    f.render_widget(p, area);
}

fn draw_editor(f: &mut Frame<'_>, state: &EditorState) {
    let area = centered_rect(86, 84, f.area());
    f.render_widget(Clear, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(area);

    let title_text = match state.target {
        EditorTarget::New => "New entry",
        EditorTarget::Existing(_) => "Edit entry",
    };

    let header = Paragraph::new(format!(
        "{}  |  Tab/↓ next  | ↑ previous  |  Enter -> advances  | ",
        title_text
    ))
    .block(Block::default().borders(Borders::ALL).title("editor"));
    f.render_widget(header, chunks[0]);

    let title = Paragraph::new(state.draft.title.clone())
        .block(Block::default().borders(Borders::ALL).title("Title"))
        .style(if state.focus == Focus::Title {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default()
        });
    f.render_widget(title, chunks[1]);

    let username = Paragraph::new(state.draft.username.clone())
        .block(Block::default().borders(Borders::ALL).title("Username"))
        .style(if state.focus == Focus::Username {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default()
        });
    f.render_widget(username, chunks[2]);

    let password_display = if state.show_pass {
        state.draft.password.clone()
    } else {
        mask_password(&state.draft.password)
    };

    let password = Paragraph::new(password_display)
        .block(Block::default().borders(Borders::ALL).title("Password"))
        .style(if state.focus == Focus::Password {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default()
        });
    f.render_widget(password, chunks[3]);

    let toggle_row = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(22),
            Constraint::Percentage(22),
        ])
        .split(chunks[4]);

    let toggle_label = if state.show_pass {
        "[x] Show"
    } else {
        "[ ] Show"
    };

    let toggle_btn = button_block(
        toggle_label,
        state.focus == Focus::ShowPassword,
    );

    let generate = button_block(
        "<  Generate  >",
        state.focus == Focus::GenPassword,
    );

    f.render_widget(toggle_btn, toggle_row[0]);
    f.render_widget(generate, toggle_row[1]);

    let notes = Paragraph::new(state.draft.notes.clone())
        .block(Block::default().borders(Borders::ALL).title("Notes"))
        .wrap(Wrap { trim: false })
        .style(if state.focus == Focus::Notes {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default()
        });
    f.render_widget(notes, chunks[5]);

    let button_area = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(chunks[6]);

    fn button_block<'a>(title: &'a str, focused: bool) -> Paragraph<'a> {
        Paragraph::new(title)
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL))
            .style(
                  if focused {
                    Style::default().add_modifier(Modifier::REVERSED)
                } else {
                    Style::default()
                },
            )
    }

    let save = button_block(
        "<  Continue  >",
        state.focus == Focus::Save,
    );

    let toggle_label = if state.show_pass { "[x] Show" } else { "[ ] Show" };

    let _toggle = button_block(
        toggle_label,
        state.focus == Focus::ShowPassword,
    );

    let cancel = button_block(
        "<  Cancel  >",
        state.focus == Focus::Cancel,
    );

    f.render_widget(save, button_area[0]);
    f.render_widget(cancel, button_area[1]);
}

fn draw_delete_confirm(f: &mut Frame<'_>, entry: Option<&Entry>) {
    let area = centered_rect(60, 28, f.area());
    f.render_widget(Clear, area);

    let title = entry
        .map(|e| {
            if e.title.trim().is_empty() {
                "(untitled)"
            } else {
                e.title.as_str()
            }
        })
        .unwrap_or("entry");

    let text = format!(
        "Delete this entry?\n\n{}\n\nPress Y to delete, N or Esc to cancel.",
        title
    );

    let p = Paragraph::new(text)
        .wrap(Wrap { trim: false })
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).title("confirm delete"));

    f.render_widget(p, area);
}

pub fn tui_text_modal(prompt: &str) -> Result<String> {
    input_modal(prompt, false)
}

pub fn tui_password_modal(prompt: &str) -> Result<String> {
    input_modal(prompt, true)
}

pub fn tui_message(message: &str) -> Result<()> {
    let mut term = setup_terminal()?;

    let res = (|| -> Result<()> {
        loop {
            term.draw(|f| {
                let area = centered_rect(60, 22, f.area());
                f.render_widget(Clear, area);

                let vertical_pad = area.height.saturating_sub(3) / 2;
                let p = Paragraph::new(format!(
                    "{}{}",
                    "\n".repeat(vertical_pad as usize),
                    message
                ))
                .alignment(Alignment::Center)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("message"),
                );

                f.render_widget(p, area);
            })?;

            if let Event::Key(KeyEvent { code, .. }) = event::read()? {
                match code {
                    KeyCode::Enter | KeyCode::Esc | KeyCode::Char(_) => break,
                    _ => {}
                }
            }
        }
        Ok(())
    })();

    restore_terminal(&mut term)?;
    res
}

fn input_modal(prompt: &str, secret: bool) -> Result<String> {
    let mut term = setup_terminal()?;
    let mut buf = String::new();

    let res = (|| -> Result<String> {
        loop {
            term.draw(|f| {
                let area = centered_rect(26, 7, f.area());
                f.render_widget(Clear, area);

                let display = if secret {
                    mask_password(&buf)
                } else {
                    buf.clone()
                };

                let p = Paragraph::new(display)
                    .block(Block::default().borders(Borders::ALL).title(prompt));

                f.render_widget(p, area);
            })?;

            if let Event::Key(KeyEvent { code, .. }) = event::read()? {
                match code {
                    KeyCode::Char(c) => buf.push(c),
                    KeyCode::Backspace => {
                        buf.pop();
                    }
                    KeyCode::Enter => break,
                    KeyCode::Esc => {
                        buf.clear();
                        break;
                    }
                    _ => {}
                }
            }
        }
        Ok(buf)
    })();

    restore_terminal(&mut term)?;
    res
}