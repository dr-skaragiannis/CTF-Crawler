//! ctf-logger - attacker-side (Kali) recorder for a CTF challenge.
//!
//! While running it stores, live, under /home/<user>/CTF-Logs/<challenge>/<timestamp>/:
//!   pcap/<iface>.pcap        one tcpdump per network interface (new ones such as tun0 are
//!                            picked up automatically, restarted ones get .partN files)
//!   pcap/target_<ip>.pcap    all traffic to/from the target IP on any interface
//!   terminals/*.typescript   full recording (input + output) of every terminal opened
//!   terminals/*.txt          the same, cleaned of escape codes (written on stop)
//!   commands.log             every command: time, user@host, terminal, cwd, exit code
//!   session_info.txt / events.log
//!
//! Usage:  sudo ctf-logger              start a session (asks challenge name + target IP)
//!         sudo ctf-logger --uninstall  remove the shell hooks from the rc files

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ctf_logger::{
    chown_recursive, dir_size, human_size, invoking_user, is_root, log_root, now_human, prompt,
    prompt_ip, sanitize, timestamp, which, EventLog, UserInfo,
};

const HOOK_DIR: &str = "/etc/ctf-logger";
const HOOK_PATH: &str = "/etc/ctf-logger/hook.sh";
const HOOK_TEMPLATE: &str = include_str!("hook.sh");
const RC_MARK: &str = "# CTF-LOGGER hook";
const RC_FILES: [&str; 2] = [".bashrc", ".zshrc"];
/// Give up on an interface after this many tcpdump crashes in a row.
const MAX_FAILS: u32 = 5;
const STATUS_EVERY: Duration = Duration::from_secs(30);

struct Capture {
    iface: String,
    stem: String,
    filter: Vec<String>,
    child: Option<Child>,
    part: u32,
    fails: u32,
    started: Instant,
}

impl Capture {
    fn new(iface: &str, stem: &str, filter: Vec<String>) -> Self {
        Self {
            iface: iface.to_string(),
            stem: stem.to_string(),
            filter,
            child: None,
            part: 0,
            fails: 0,
            started: Instant::now(),
        }
    }

    fn start(&mut self, pcap_dir: &Path, err_log: &File) -> io::Result<PathBuf> {
        self.part += 1;
        let name = if self.part == 1 {
            format!("{}.pcap", self.stem)
        } else {
            format!("{}.part{}.pcap", self.stem, self.part)
        };
        let out = pcap_dir.join(name);
        let child = Command::new("tcpdump")
            // -U: flush every packet so the pcap is usable live; -Z root: don't drop to the
            // tcpdump user, which could not write into a 0700 home directory.
            .args(["-i", &self.iface, "-U", "-n", "-s", "0", "-Z", "root", "-w"])
            .arg(&out)
            .args(&self.filter)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(err_log.try_clone()?))
            // own process group: Ctrl+C in this terminal must not kill tcpdump before we
            // stop it cleanly
            .process_group(0)
            .spawn()?;
        self.child = Some(child);
        self.started = Instant::now();
        Ok(out)
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("[!] {e}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    if !is_root() {
        return Err(io::Error::other("root is required for packet capture: sudo ctf-logger"));
    }
    let user = invoking_user()?;
    let root = log_root(&user);

    if std::env::args().nth(1).as_deref() == Some("--uninstall") {
        return uninstall_hooks(&user);
    }
    for bin in ["tcpdump", "script"] {
        if !which(bin) {
            return Err(io::Error::other(format!("'{bin}' not found (apt install tcpdump bsdutils)")));
        }
    }

    println!("=== CTF-Logger ===  logs go to {}\n", root.display());
    let challenge = sanitize(&prompt("Challenge name", None)?);
    let target = prompt_ip("Target (victim) IP address", None)?;

    let session = root.join(&challenge).join(timestamp());
    let pcap_dir = session.join("pcap");
    let term_dir = session.join("terminals");
    fs::create_dir_all(&pcap_dir)?;
    fs::create_dir_all(&term_dir)?;
    // Shells of the normal user and of root both write here.
    fs::set_permissions(&term_dir, fs::Permissions::from_mode(0o1777))?;
    let commands_log = session.join("commands.log");
    fs::write(&commands_log, "# time\tuser@host\tterminal\tcwd\texit\tcommand\n")?;
    fs::set_permissions(&commands_log, fs::Permissions::from_mode(0o666))?;
    chown_recursive(&root, user.uid, user.gid)?;

    let mut events = EventLog::open(&session.join("events.log"))?;
    let tcpdump_err = OpenOptions::new().create(true).append(true).open(session.join("tcpdump.log"))?;
    write_session_info(&session, &challenge, &target.to_string(), &user)?;

    let marker = root.join(".active_session");
    fs::write(&marker, format!("{}\n{}\n", session.display(), std::process::id()))?;
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o644))?;
    for rc in install_hooks(&user, &marker)? {
        events.log(&format!("shell hook installed in {}", rc.display()));
    }

    let running = Arc::new(AtomicBool::new(true));
    {
        let running = running.clone();
        ctrlc::set_handler(move || running.store(false, Ordering::SeqCst))
            .map_err(io::Error::other)?;
    }

    events.log(&format!("session started: challenge={challenge} target={target}"));
    events.log(&format!("session folder: {}", session.display()));
    println!("\n>>> Open NEW terminals now - every new bash/zsh is recorded. Ctrl+C here to stop.\n");

    let target_stem = format!("target_{}", target.to_string().replace(':', "_"));
    let mut caps: BTreeMap<String, Capture> = BTreeMap::new();
    caps.insert(
        target_stem.clone(),
        Capture::new("any", &target_stem, vec!["host".into(), target.to_string()]),
    );
    let mut last_status = Instant::now();

    while running.load(Ordering::SeqCst) {
        let ifaces = list_interfaces();
        for iface in &ifaces {
            caps.entry(iface.clone()).or_insert_with(|| Capture::new(iface, iface, Vec::new()));
        }

        for cap in caps.values_mut() {
            let present = cap.iface == "any" || ifaces.contains(&cap.iface);
            if let Some(child) = cap.child.as_mut() {
                if let Ok(Some(status)) = child.try_wait() {
                    events.log(&format!("tcpdump on {} exited ({status})", cap.iface));
                    cap.child = None;
                    if !present || cap.started.elapsed() > Duration::from_secs(10) {
                        cap.fails = 0;
                    } else {
                        cap.fails += 1;
                    }
                }
            }
            if cap.child.is_none() && present && cap.fails < MAX_FAILS && running.load(Ordering::SeqCst) {
                match cap.start(&pcap_dir, &tcpdump_err) {
                    Ok(out) => events.log(&format!(
                        "capturing {}{} -> {}",
                        cap.iface,
                        if cap.filter.is_empty() { String::new() } else { format!(" [{}]", cap.filter.join(" ")) },
                        out.file_name().unwrap().to_string_lossy()
                    )),
                    Err(e) => {
                        cap.fails += 1;
                        events.log(&format!("cannot start tcpdump on {}: {e}", cap.iface));
                    }
                }
                if cap.fails == MAX_FAILS {
                    events.log(&format!("giving up on {} (see tcpdump.log)", cap.iface));
                }
            }
        }

        if last_status.elapsed() >= STATUS_EVERY {
            last_status = Instant::now();
            print_status(&session, &caps);
        }
        thread::sleep(Duration::from_secs(1));
    }

    println!();
    events.log("stopping...");
    stop_captures(&mut caps);
    let _ = fs::remove_file(&marker);
    let cleaned = clean_typescripts(&term_dir);
    events.log(&format!("wrote {cleaned} cleaned terminal transcript(s) (.txt)"));
    let mut info = OpenOptions::new().append(true).open(session.join("session_info.txt"))?;
    writeln!(info, "Stopped:        {}", now_human())?;
    events.log("session stopped");
    chown_recursive(&session, user.uid, user.gid)?;

    print_status(&session, &caps);
    println!("\nSaved in {}", session.display());
    println!("Terminals still open keep writing their .typescript until closed.");
    println!("Shell hooks stay installed but are inactive; remove them with: sudo ctf-logger --uninstall");
    Ok(())
}

/// Every interface in /sys/class/net (directories only; skips e.g. bonding_masters).
fn list_interfaces() -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir("/sys/class/net")
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter(|e| e.path().is_dir())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn stop_captures(caps: &mut BTreeMap<String, Capture>) {
    for cap in caps.values() {
        if let Some(child) = &cap.child {
            // SIGINT lets tcpdump flush and close the pcap properly.
            unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) };
        }
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    for cap in caps.values_mut() {
        if let Some(mut child) = cap.child.take() {
            while Instant::now() < deadline {
                if let Ok(Some(_)) = child.try_wait() {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
            if let Ok(None) = child.try_wait() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

fn print_status(session: &Path, caps: &BTreeMap<String, Capture>) {
    let active = caps.values().filter(|c| c.child.is_some()).count();
    let commands = fs::read_to_string(session.join("commands.log"))
        .map(|s| s.lines().filter(|l| !l.starts_with('#')).count())
        .unwrap_or(0);
    let terminals = fs::read_dir(session.join("terminals"))
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|x| x == "typescript"))
                .count()
        })
        .unwrap_or(0);
    println!(
        "[status] tcpdump running: {active} | pcap: {} | terminals: {terminals} | commands: {commands}",
        human_size(dir_size(&session.join("pcap")))
    );
}

fn write_session_info(session: &Path, challenge: &str, target: &str, user: &UserInfo) -> io::Result<()> {
    let run = |cmd: &str, args: &[&str]| {
        Command::new(cmd)
            .args(args)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_else(|e| format!("({cmd}: {e})\n"))
    };
    let mut f = File::create(session.join("session_info.txt"))?;
    writeln!(f, "Challenge:      {challenge}")?;
    writeln!(f, "Target IP:      {target}")?;
    writeln!(f, "Attacker user:  {}", user.name)?;
    writeln!(f, "Attacker host:  {}", run("uname", &["-a"]).trim())?;
    writeln!(f, "Started:        {}", now_human())?;
    writeln!(f, "\n--- ip -br addr ---\n{}", run("ip", &["-br", "addr"]))?;
    writeln!(f, "--- ip route ---\n{}", run("ip", &["route"]))?;
    Ok(())
}

/// Home directories whose shells should be hooked: the invoking user's and root's.
fn hooked_homes(user: &UserInfo) -> Vec<(PathBuf, u32, u32)> {
    let mut homes = vec![(user.home.clone(), user.uid, user.gid)];
    if user.home != Path::new("/root") {
        homes.push((PathBuf::from("/root"), 0, 0));
    }
    homes
}

fn install_hooks(user: &UserInfo, marker: &Path) -> io::Result<Vec<PathBuf>> {
    fs::create_dir_all(HOOK_DIR)?;
    fs::write(HOOK_PATH, HOOK_TEMPLATE.replace("{{MARKER}}", &marker.to_string_lossy()))?;
    fs::set_permissions(HOOK_PATH, fs::Permissions::from_mode(0o644))?;

    let line = format!("[ -r {HOOK_PATH} ] && . {HOOK_PATH}  {RC_MARK}\n");
    let mut installed = Vec::new();
    for (home, uid, gid) in hooked_homes(user) {
        for rc_name in RC_FILES {
            let rc = home.join(rc_name);
            let existed = rc.exists();
            // A missing .zshrc is left alone; a missing .bashrc is created.
            if !existed && rc_name != ".bashrc" {
                continue;
            }
            let content = fs::read_to_string(&rc).unwrap_or_default();
            if content.contains(RC_MARK) {
                continue;
            }
            let mut f = OpenOptions::new().create(true).append(true).open(&rc)?;
            if !content.is_empty() && !content.ends_with('\n') {
                f.write_all(b"\n")?;
            }
            f.write_all(line.as_bytes())?;
            if !existed {
                std::os::unix::fs::chown(&rc, Some(uid), Some(gid))?;
            }
            installed.push(rc);
        }
    }
    Ok(installed)
}

fn uninstall_hooks(user: &UserInfo) -> io::Result<()> {
    for (home, _, _) in hooked_homes(user) {
        for rc_name in RC_FILES {
            let rc = home.join(rc_name);
            let Ok(content) = fs::read_to_string(&rc) else { continue };
            if !content.contains(RC_MARK) {
                continue;
            }
            let kept: String = content
                .lines()
                .filter(|l| !l.contains(RC_MARK))
                .map(|l| format!("{l}\n"))
                .collect();
            fs::write(&rc, kept)?; // rewriting in place keeps owner and mode
            println!("removed hook from {}", rc.display());
        }
    }
    let _ = fs::remove_dir_all(HOOK_DIR);
    println!("done");
    Ok(())
}

/// Write a readable `.txt` next to every `.typescript`. Returns how many were written.
fn clean_typescripts(dir: &Path) -> usize {
    let Ok(rd) = fs::read_dir(dir) else { return 0 };
    let mut n = 0;
    for entry in rd.filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().is_some_and(|x| x == "typescript") {
            if let Ok(raw) = fs::read(&path) {
                if fs::write(path.with_extension("txt"), strip_terminal_codes(&raw)).is_ok() {
                    n += 1;
                }
            }
        }
    }
    n
}

/// Remove ANSI/VT escape sequences and apply backspaces/carriage returns, so a raw
/// terminal recording reads like plain text.
fn strip_terminal_codes(raw: &[u8]) -> String {
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
