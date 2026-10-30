//! Helpers shared by `ctf-logger` (attacker side) and `ctf-victim-logs` (victim side).

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use chrono::Local;

/// A local account, as found in /etc/passwd.
pub struct UserInfo {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// The human behind the program: `$SUDO_USER` when started through sudo, otherwise `$USER`.
pub fn invoking_user() -> io::Result<UserInfo> {
    let name = std::env::var("SUDO_USER")
        .ok()
        .filter(|u| !u.is_empty() && u != "root")
        .or_else(|| std::env::var("USER").ok().filter(|u| !u.is_empty()))
        .unwrap_or_else(|| "root".to_string());
    lookup_user(&name)
}

pub fn lookup_user(name: &str) -> io::Result<UserInfo> {
    let passwd = fs::read_to_string("/etc/passwd")?;
    for line in passwd.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() >= 7 && f[0] == name {
            return Ok(UserInfo {
                name: name.to_string(),
                uid: f[2].parse().unwrap_or(0),
                gid: f[3].parse().unwrap_or(0),
                home: PathBuf::from(f[5]),
            });
        }
    }
    Err(io::Error::other(format!("user '{name}' not found in /etc/passwd")))
}

/// `/home/<user>/CTF-Logs` (or the user's real home directory from /etc/passwd).
pub fn log_root(user: &UserInfo) -> PathBuf {
    user.home.join("CTF-Logs")
}

pub fn prompt(label: &str, default: Option<&str>) -> io::Result<String> {
    let default = default.filter(|d| !d.is_empty());
    loop {
        match default {
            Some(d) => print!("{label} [{d}]: "),
            None => print!("{label}: "),
        }
        io::stdout().flush()?;
        let mut line = String::new();
        if io::stdin().read_line(&mut line)? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "stdin closed"));
        }
        let line = line.trim();
        if !line.is_empty() {
            return Ok(line.to_string());
        }
        if let Some(d) = default {
            return Ok(d.to_string());
        }
    }
}

/// Read a line from the terminal without echoing it (for passwords).
pub fn prompt_password(label: &str) -> io::Result<String> {
    print!("{label}: ");
    io::stdout().flush()?;
    let fd = libc::STDIN_FILENO;
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    let is_tty = unsafe { libc::tcgetattr(fd, &mut saved) } == 0;
    if is_tty {
        let mut silent = saved;
        silent.c_lflag &= !libc::ECHO;
        silent.c_lflag |= libc::ECHONL;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &silent) };
    }
    let mut line = String::new();
    let read = io::stdin().read_line(&mut line);
    if is_tty {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
    }
    if read? == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "stdin closed"));
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

pub fn prompt_ip(label: &str, default: Option<&str>) -> io::Result<IpAddr> {
    loop {
        match prompt(label, default)?.parse() {
            Ok(ip) => return Ok(ip),
            Err(_) => eprintln!("    not a valid IPv4/IPv6 address, try again"),
        }
    }
}

pub fn prompt_yes_no(label: &str, default_yes: bool) -> io::Result<bool> {
    let hint = if default_yes { "Y/n" } else { "y/N" };
    let answer = prompt(&format!("{label} ({hint})"), Some(if default_yes { "y" } else { "n" }))?;
    Ok(answer.to_ascii_lowercase().starts_with('y'))
}

/// Make a challenge name safe to use as a directory name.
pub fn sanitize(name: &str) -> String {
    let s: String = name
        .trim()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || "-_.".contains(c) { c } else { '_' })
        .collect();
    let s = s.trim_matches('.').to_string();
    if s.is_empty() { "challenge".to_string() } else { s }
}

/// Timestamp usable in file names.
pub fn timestamp() -> String {
    Local::now().format("%Y-%m-%d_%H-%M-%S").to_string()
}

pub fn now_human() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S %z").to_string()
}

pub fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
        .unwrap_or(false)
}

pub fn chown_recursive(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    std::os::unix::fs::lchown(path, Some(uid), Some(gid))?;
    if fs::symlink_metadata(path)?.is_dir() {
        for entry in fs::read_dir(path)? {
            chown_recursive(&entry?.path(), uid, gid)?;
        }
    }
    Ok(())
}

/// Append-only, timestamped log that is also echoed to the console.
pub struct EventLog {
    file: fs::File,
}

impl EventLog {
    pub fn open(path: &Path) -> io::Result<Self> {
        Ok(Self { file: OpenOptions::new().create(true).append(true).open(path)? })
    }

    pub fn log(&mut self, msg: &str) {
        println!("[{}] {msg}", Local::now().format("%H:%M:%S"));
        let _ = writeln!(self.file, "[{}] {msg}", now_human());
    }
}

/// Newest sub-directory of `dir` (by mtime), if any.
pub fn newest_subdir(dir: &Path) -> Option<PathBuf> {
    fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
        .max_by_key(|e| e.metadata().and_then(|m| m.modified()).ok())
        .map(|e| e.path())
}

pub fn dir_size(path: &Path) -> u64 {
    let Ok(meta) = fs::symlink_metadata(path) else { return 0 };
    if !meta.is_dir() {
        return meta.len();
    }
    fs::read_dir(path)
        .map(|rd| rd.filter_map(Result::ok).map(|e| dir_size(&e.path())).sum())
        .unwrap_or(0)
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{bytes} B") } else { format!("{v:.1} {}", UNITS[i]) }
}
