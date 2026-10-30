//! ctf-logger - attacker-side (Kali) recorder for a CTF challenge.
//!
//! While running it stores, live, under /home/<user>/CTF-Logs/<challenge>/<timestamp>/:
//!   pcap/<iface>.pcap          one tcpdump per network interface (new ones such as tun0 are
//!                              picked up automatically, restarted ones get .partN files)
//!   pcap/target_<ip>.pcap      all traffic to/from the target IP on any interface
//!   terminal_output.log        every command of every terminal with its own output,
//!                              time, user, cwd, exit code and duration (chronological)
//!   terminals/<id>.log         the same, per terminal
//!   terminals/<id>.txt         whole terminal, cleaned of escape codes
//!   terminals/<id>.typescript  raw recording (+ .timing for scriptreplay, .idx offsets)
//!   commands.log               one line per command
//!   browser/tls_keys.log       TLS keys of Firefox/Chrome (decrypt HTTPS in Wireshark)
//!   browser/history.tsv        pages visited and files downloaded during the session
//!   burp/burp_http.log         every Burp request/response (with the Burp extension)
//!   session_info.txt / events.log
//!
//! Usage:  sudo ctf-logger              start a session (asks challenge name + target IP)
//!         sudo ctf-logger --uninstall  remove the shell hooks and browser launchers

mod transcript;

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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ctf_logger::{
    chown_recursive, dir_size, human_size, invoking_user, is_root, log_root, now_human, prompt,
    prompt_ip, sanitize, timestamp, which, EventLog, UserInfo,
};

const HOOK_DIR: &str = "/etc/ctf-logger";
const HOOK_PATH: &str = "/etc/ctf-logger/hook.sh";
const WRAP_PATH: &str = "/etc/ctf-logger/browser-wrap.sh";
const HISTORY_PATH: &str = "/etc/ctf-logger/browser_history.py";
const BURP_PATH: &str = "/etc/ctf-logger/ctf_burp_logger.py";
const HOOK_TEMPLATE: &str = include_str!("hook.sh");
const WRAP_TEMPLATE: &str = include_str!("browser-wrap.sh");
const HISTORY_SCRIPT: &str = include_str!("browser_history.py");
const BURP_TEMPLATE: &str = include_str!("../burp/ctf_burp_logger.py");
const RC_MARK: &str = "# CTF-LOGGER hook";
const RC_FILES: [&str; 2] = [".bashrc", ".zshrc"];
const DESKTOP_MARK: &str = "X-CTF-Logger-Override=true";
/// Browser launchers that get an override sending them through browser-wrap.sh.
const BROWSER_DESKTOP_FILES: [&str; 6] = [
    "firefox-esr.desktop",
    "firefox.desktop",
    "google-chrome.desktop",
    "chromium.desktop",
    "chromium-browser.desktop",
    "brave-browser.desktop",
];
/// Give up on an interface after this many tcpdump crashes in a row.
const MAX_FAILS: u32 = 5;
const STATUS_EVERY: Duration = Duration::from_secs(30);
const RENDER_EVERY: Duration = Duration::from_secs(5);
const HISTORY_EVERY: Duration = Duration::from_secs(60);

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
        return uninstall(&user);
    }
    for bin in ["tcpdump", "script"] {
        if !which(bin) {
            return Err(io::Error::other(format!("'{bin}' not found (apt install tcpdump bsdutils)")));
        }
    }

    println!("=== CTF-Logger ===  logs go to {}\n", root.display());
    let challenge = sanitize(&prompt("Challenge name", None)?);
    let target = prompt_ip("Target (victim) IP address", None)?;
    let started_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();

    let session = root.join(&challenge).join(timestamp());
    let pcap_dir = session.join("pcap");
    let term_dir = session.join("terminals");
    for dir in [&pcap_dir, &term_dir, &session.join("browser"), &session.join("burp")] {
        fs::create_dir_all(dir)?;
    }
    // Shells, browsers and Burp of the normal user and of root all write here.
    fs::set_permissions(&term_dir, fs::Permissions::from_mode(0o1777))?;
    let commands_log = session.join("commands.log");
    fs::write(&commands_log, "# time\tuser@host\tterminal\tcwd\texit\tcommand\n")?;
    let tls_keys = session.join("browser").join("tls_keys.log");
    fs::write(&tls_keys, "")?;
    for f in [&commands_log, &tls_keys] {
        fs::set_permissions(f, fs::Permissions::from_mode(0o666))?;
    }
    chown_recursive(&root, user.uid, user.gid)?;

    let mut events = EventLog::open(&session.join("events.log"))?;
    let tcpdump_err = OpenOptions::new().create(true).append(true).open(session.join("tcpdump.log"))?;
    write_session_info(&session, &challenge, &target.to_string(), &user)?;

    let marker = root.join(".active_session");
    fs::write(&marker, format!("{}\n{}\n", session.display(), std::process::id()))?;
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o644))?;
    for path in install(&user, &marker)? {
        events.log(&format!("hook installed: {}", path.display()));
    }

    let running = Arc::new(AtomicBool::new(true));
    {
        let running = running.clone();
        ctrlc::set_handler(move || running.store(false, Ordering::SeqCst))
            .map_err(io::Error::other)?;
    }

    events.log(&format!("session started: challenge={challenge} target={target}"));
    events.log(&format!("session folder: {}", session.display()));
    println!("\n>>> Open NEW terminals now - every new bash/zsh is recorded.");
    println!(">>> (Re)start Firefox/Chrome from the menu or a recorded terminal to log their TLS keys.");
    println!(">>> Burp: load {BURP_PATH} once (Extensions > Add > Python).");
    println!(">>> Ctrl+C here to stop.\n");

    let target_stem = format!("target_{}", target.to_string().replace(':', "_"));
    let mut caps: BTreeMap<String, Capture> = BTreeMap::new();
    caps.insert(
        target_stem.clone(),
        Capture::new("any", &target_stem, vec!["host".into(), target.to_string()]),
    );
    let homes: Vec<PathBuf> = hooked_homes(&user).into_iter().map(|(h, _, _)| h).collect();
    let mut last_status = Instant::now();
    let mut last_render = Instant::now();
    let mut last_history = Instant::now();
    let mut rendered_size = 0;

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

        if last_render.elapsed() >= RENDER_EVERY {
            last_render = Instant::now();
            let size = recording_size(&term_dir);
            if size != rendered_size {
                rendered_size = size;
                let _ = transcript::render_session(&session);
            }
        }
        if last_history.elapsed() >= HISTORY_EVERY {
            last_history = Instant::now();
            export_browser_history(&session, started_epoch, &homes);
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
    match transcript::render_session(&session) {
        Ok(n) => events.log(&format!("terminal_output.log: {n} command(s) with their output")),
        Err(e) => events.log(&format!("could not render terminal transcripts: {e}")),
    }
    export_browser_history(&session, started_epoch, &homes);
    let mut info = OpenOptions::new().append(true).open(session.join("session_info.txt"))?;
    writeln!(info, "Stopped:        {}", now_human())?;
    events.log("session stopped");
    chown_recursive(&session, user.uid, user.gid)?;

    print_status(&session, &caps);
    println!("\nSaved in {}", session.display());
    println!("Terminals still open keep writing their .typescript until closed.");
    println!("Hooks stay installed but are inactive; remove them with: sudo ctf-logger --uninstall");
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

/// Firefox/Chrome history + downloads since the session started -> browser/history.tsv.
fn export_browser_history(session: &Path, since: f64, homes: &[PathBuf]) {
    if !which("python3") {
        return;
    }
    let _ = Command::new("python3")
        .arg(HISTORY_PATH)
        .arg(since.to_string())
        .arg(session.join("browser").join("history.tsv"))
        .args(homes)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Total size of the raw recordings (.typescript + .idx), i.e. not of what we render.
fn recording_size(term_dir: &Path) -> u64 {
    fs::read_dir(term_dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|x| x == "typescript" || x == "idx"))
                .filter_map(|e| e.metadata().ok())
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0)
}

fn count_lines(path: &Path) -> usize {
    fs::read_to_string(path)
        .map(|s| s.lines().filter(|l| !l.starts_with('#') && !l.is_empty()).count())
        .unwrap_or(0)
}

fn print_status(session: &Path, caps: &BTreeMap<String, Capture>) {
    let active = caps.values().filter(|c| c.child.is_some()).count();
    let terminals = fs::read_dir(session.join("terminals"))
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|x| x == "typescript"))
                .count()
        })
        .unwrap_or(0);
    println!(
        "[status] tcpdump: {active} | pcap: {} | terminals: {terminals} | commands: {} | \
         browser pages: {} | TLS keys: {} | burp requests: {}",
        human_size(dir_size(&session.join("pcap"))),
        count_lines(&session.join("commands.log")),
        count_lines(&session.join("browser").join("history.tsv")),
        count_lines(&session.join("browser").join("tls_keys.log")),
        count_lines(&session.join("burp").join("burp_requests.tsv")),
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

fn write_mode(path: &str, content: &str, mode: u32) -> io::Result<()> {
    fs::write(path, content)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

/// Install the helper scripts, the shell hooks and the browser launcher overrides.
/// Returns the rc / launcher files that were changed.
fn install(user: &UserInfo, marker: &Path) -> io::Result<Vec<PathBuf>> {
    let marker = marker.to_string_lossy();
    fs::create_dir_all(HOOK_DIR)?;
    write_mode(HOOK_PATH, &HOOK_TEMPLATE.replace("{{MARKER}}", &marker), 0o644)?;
    write_mode(WRAP_PATH, &WRAP_TEMPLATE.replace("{{MARKER}}", &marker), 0o755)?;
    write_mode(HISTORY_PATH, HISTORY_SCRIPT, 0o644)?;
    write_mode(BURP_PATH, &BURP_TEMPLATE.replace("{{MARKER}}", &marker), 0o644)?;

    let line = format!("[ -r {HOOK_PATH} ] && . {HOOK_PATH}  {RC_MARK}\n");
    let mut changed = Vec::new();
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
            changed.push(rc);
        }
    }
    changed.extend(install_browser_launchers(user)?);
    Ok(changed)
}

/// Copy each installed browser's .desktop file to ~/.local/share/applications (which
/// takes precedence) with every Exec= line routed through browser-wrap.sh.
fn install_browser_launchers(user: &UserInfo) -> io::Result<Vec<PathBuf>> {
    let apps = user.home.join(".local/share/applications");
    let mut changed = Vec::new();
    for name in BROWSER_DESKTOP_FILES {
        let Ok(system) = fs::read_to_string(Path::new("/usr/share/applications").join(name)) else {
            continue;
        };
        let target = apps.join(name);
        if let Ok(existing) = fs::read_to_string(&target) {
            if !existing.contains(DESKTOP_MARK) {
                continue; // the user's own override: leave it alone
            }
        }
        let mut out = String::new();
        for line in system.lines() {
            match line.strip_prefix("Exec=") {
                Some(cmd) if !cmd.starts_with(WRAP_PATH) => out.push_str(&format!("Exec={WRAP_PATH} {cmd}\n")),
                _ => out.push_str(&format!("{line}\n")),
            }
            if line.trim() == "[Desktop Entry]" {
                out.push_str(&format!("{DESKTOP_MARK}\n"));
            }
        }
        fs::create_dir_all(&apps)?;
        fs::write(&target, out)?;
        chown_recursive(&user.home.join(".local/share/applications"), user.uid, user.gid)?;
        changed.push(target);
    }
    Ok(changed)
}

fn uninstall(user: &UserInfo) -> io::Result<()> {
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
    let apps = user.home.join(".local/share/applications");
    for name in BROWSER_DESKTOP_FILES {
        let path = apps.join(name);
        if fs::read_to_string(&path).is_ok_and(|c| c.contains(DESKTOP_MARK)) {
            fs::remove_file(&path)?;
            println!("removed launcher override {}", path.display());
        }
    }
    let _ = fs::remove_dir_all(HOOK_DIR);
    println!("done (unload the CTF-Logger extension in Burp yourself)");
    Ok(())
}
