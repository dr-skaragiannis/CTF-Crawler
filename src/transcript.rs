//! Turns raw terminal recordings into readable per-command transcripts.
//!
//! For every terminal the shell hook writes `<id>.typescript` (raw bytes from `script`)
//! and `<id>.idx`, one line per command start/end with the byte offset of the recording:
//!   S <epoch> <offset> <user@host> <cwd> <command>
//!   E <epoch> <offset> <exit code>
//! The output of a command is the recording between its S and E offsets.

use std::fs;
use std::io;
use std::path::Path;

use chrono::{Local, TimeZone};

struct Block {
    term: String,
    start: f64,
    end: Option<f64>,
    from: usize,
    to: Option<usize>,
    who: String,
    cwd: String,
    cmd: String,
    exit: Option<String>,
}

const RULE: &str = "================================================================================";
const THIN: &str = "--------------------------------------------------------------------------------";

/// Write `<id>.txt` (whole terminal, cleaned), `<id>.log` (per command) for every
/// terminal and `terminal_output.log` (all terminals, chronological) for the session.
/// Returns the number of commands rendered.
pub fn render_session(session: &Path) -> io::Result<usize> {
    let term_dir = session.join("terminals");
    let mut all: Vec<(Block, String)> = Vec::new();

    for entry in fs::read_dir(&term_dir)?.filter_map(Result::ok) {
        let ts_path = entry.path();
        if !ts_path.extension().is_some_and(|x| x == "typescript") {
            continue;
        }
        let Ok(raw) = fs::read(&ts_path) else { continue };
        let term = ts_path.file_stem().unwrap().to_string_lossy().into_owned();
        let _ = fs::write(ts_path.with_extension("txt"), strip_terminal_codes(&raw));

        let idx = fs::read_to_string(ts_path.with_extension("idx")).unwrap_or_default();
        let mut per_term = String::new();
        for block in parse_index(&term, &idx) {
            let to = block.to.unwrap_or(raw.len()).min(raw.len());
            let from = block.from.min(to);
            let output = strip_terminal_codes(&raw[from..to]);
            let text = format_block(&block, output.trim_matches('\n'));
            per_term.push_str(&text);
            all.push((block, text));
        }
        let _ = fs::write(ts_path.with_extension("log"), per_term);
    }

    all.sort_by(|a, b| a.0.start.total_cmp(&b.0.start));
    let merged: String = all.iter().map(|(_, t)| t.as_str()).collect();
    fs::write(session.join("terminal_output.log"), merged)?;
    Ok(all.len())
}

fn parse_index(term: &str, idx: &str) -> Vec<Block> {
    let mut blocks: Vec<Block> = Vec::new();
    // Commands can nest (e.g. `sudo -E bash`), so an end closes the newest open start.
    let mut open: Vec<usize> = Vec::new();
    for line in idx.lines() {
        let f: Vec<&str> = line.splitn(6, '\t').collect();
        match f.as_slice() {
            ["S", time, off, who, cwd, cmd] => {
                open.push(blocks.len());
                blocks.push(Block {
                    term: term.to_string(),
                    start: time.parse().unwrap_or(0.0),
                    end: None,
                    from: off.parse().unwrap_or(0),
                    to: None,
                    who: who.to_string(),
                    cwd: cwd.to_string(),
                    cmd: cmd.to_string(),
                    exit: None,
                });
            }
            ["E", time, off, exit] => {
                if let Some(i) = open.pop() {
                    let b = &mut blocks[i];
                    b.end = time.parse().ok();
                    b.to = off.parse().ok();
                    b.exit = Some(exit.to_string());
                }
            }
            _ => {}
        }
    }
    blocks
}

fn format_block(b: &Block, output: &str) -> String {
    let status = match (&b.exit, b.end) {
        (Some(exit), Some(end)) => format!("exit {exit} | {:.1} s", (end - b.start).max(0.0)),
        _ => "still running".to_string(),
    };
    format!(
        "{RULE}\n[{}] {}:{}   (terminal {})\n$ {}\n{THIN}\n{}{}[{status}]\n\n",
        fmt_time(b.start),
        b.who,
        b.cwd,
        b.term,
        b.cmd,
        output,
        if output.is_empty() { "" } else { "\n" },
    )
}

fn fmt_time(epoch: f64) -> String {
    let secs = epoch.trunc() as i64;
    let nanos = (epoch.fract() * 1e9) as u32;
    Local
        .timestamp_opt(secs, nanos)
        .single()
        .map(|t| t.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
        .unwrap_or_else(|| epoch.to_string())
}

/// Remove ANSI/VT escape sequences and apply backspaces/carriage returns, so a raw
/// terminal recording reads like plain text.
pub fn strip_terminal_codes(raw: &[u8]) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let b = raw[i];
        match b {
            0x1b => {
                i += 1;
                match raw.get(i) {
                    // CSI: ESC [ params... final byte 0x40..=0x7e
                    Some(b'[') => {
                        i += 1;
                        while i < raw.len() && !(0x40..=0x7e).contains(&raw[i]) {
                            i += 1;
                        }
                    }
                    // OSC / DCS / etc: terminated by BEL or ESC \
                    Some(b']') | Some(b'P') | Some(b'^') | Some(b'_') => {
                        i += 1;
                        while i < raw.len() {
                            if raw[i] == 0x07 {
                                break;
                            }
                            if raw[i] == 0x1b && raw.get(i + 1) == Some(&b'\\') {
                                i += 1;
                                break;
                            }
                            i += 1;
                        }
                    }
                    // charset selection: ESC ( X, ESC ) X ...
                    Some(b'(') | Some(b')') | Some(b'*') | Some(b'+') => i += 1,
                    _ => {}
                }
            }
            0x08 => {
                // backspace: drop the previous character (whole UTF-8 sequence)
                while let Some(&last) = out.last() {
                    if last == b'\n' {
                        break;
                    }
                    out.pop();
                    if last & 0xc0 != 0x80 {
                        break;
                    }
                }
            }
            b'\r' => {
                if raw.get(i + 1) != Some(&b'\n') && raw.get(i + 1) != Some(&b'\r') {
                    // bare CR: the line is being redrawn, keep only what follows
                    while let Some(&last) = out.last() {
                        if last == b'\n' {
                            break;
                        }
                        out.pop();
                    }
                }
            }
            b'\n' | b'\t' => out.push(b),
            0x00..=0x1f | 0x7f => {}
            _ => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_colors_and_redraws() {
        let raw = b"\x1b[1;32mok\x1b[0m\r\n50%\r100%\r\nab\x08c\n";
        assert_eq!(strip_terminal_codes(raw), "ok\n100%\nac\n");
    }

    #[test]
    fn pairs_nested_commands() {
        let idx = "S\t10.0\t5\tk@h\t/\tsudo -E bash\nS\t11.0\t9\tk@h\t/\tid\nE\t12.0\t20\t0\nE\t13.0\t30\t1\n";
        let b = parse_index("t", idx);
        assert_eq!(b.len(), 2);
        assert_eq!((b[0].from, b[0].to, b[0].exit.as_deref()), (5, Some(30), Some("1")));
        assert_eq!((b[1].from, b[1].to, b[1].exit.as_deref()), (9, Some(20), Some("0")));
    }
}
