//! ctf-victim-logs - collect the logs and forensic state of the VICTIM VM over SSH.
//!
//! Needs root on the victim: log in as root, or as any user that can sudo (with or without
//! a password - the sudo password is asked once and passed to `sudo -S` for every step).
//! One SSH master connection is opened (you type the SSH password/passphrase once) and
//! every collection step reuses it. Output goes to
//!   /home/<user>/CTF-Logs/<challenge>/victim_<ip>_<timestamp>/
//!     archives/*.tar.gz       /var/log, /etc, user artefacts (histories, .ssh, cron, /tmp...)
//!     <category>/*.txt        command outputs (journal, processes, network, users, files...)
//!     errors.log              stderr of every step
//!     summary.txt, MANIFEST.sha256, known_hosts
//!
//! Usage:  ctf-victim-logs

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use ctf_logger::{
    chown_recursive, human_size, invoking_user, is_root, log_root, newest_subdir, now_human,
    prompt, prompt_ip, prompt_password, prompt_yes_no, sanitize, timestamp, which,
};

/// Wrong sudo passwords accepted before giving up.
const SUDO_TRIES: u32 = 3;

/// (folder, file, remote shell script). Run with `sh -c` as root on the victim.
const COMMANDS: &[(&str, &str, &str)] = &[
    // --- system ---
    ("system", "uname.txt", "uname -a; echo; cat /etc/os-release; echo; hostnamectl 2>/dev/null"),
    ("system", "time_uptime.txt", "date; date -u; uptime; cat /proc/uptime; timedatectl 2>/dev/null"),
    ("system", "packages.txt", "dpkg -l 2>/dev/null || rpm -qa 2>/dev/null || apk info -v 2>/dev/null"),
    ("system", "mounts_disks.txt", "mount; echo; df -h; echo; lsblk 2>/dev/null"),
    ("system", "kernel_modules.txt", "lsmod"),
    ("system", "env_root.txt", "env"),
    // --- logs that live outside plain files ---
    ("logs", "journal_all.txt", "journalctl --no-pager -o short-iso-precise 2>/dev/null"),
    ("logs", "journal_kernel.txt", "journalctl --no-pager -k -o short-iso-precise 2>/dev/null"),
    ("logs", "journal_ssh.txt", "journalctl --no-pager -o short-iso-precise -u ssh -u sshd 2>/dev/null"),
    ("logs", "dmesg.txt", "dmesg -T 2>/dev/null || dmesg"),
    ("logs", "audit_report.txt", "command -v aureport >/dev/null && { aureport -i; echo; ausearch -i 2>/dev/null; }"),
    // --- users / authentication ---
    ("users", "passwd.txt", "cat /etc/passwd"),
    ("users", "shadow.txt", "cat /etc/shadow"),
    ("users", "group.txt", "cat /etc/group"),
    ("users", "sudoers.txt", "cat /etc/sudoers; for f in /etc/sudoers.d/*; do [ -f \"$f\" ] && { echo \"### $f\"; cat \"$f\"; }; done"),
    ("users", "logins_last.txt", "last -Faiwx 2>/dev/null || last"),
    ("users", "logins_failed_lastb.txt", "lastb -Faiw 2>/dev/null || lastb"),
    ("users", "lastlog.txt", "lastlog 2>/dev/null || lastlog2 2>/dev/null"),
    ("users", "who_w.txt", "who -a; echo; w"),
    ("users", "shell_histories.txt",
        "for f in /root/.*history /home/*/.*history /home/*/.local/share/fish/fish_history /root/.local/share/fish/fish_history; do \
           [ -f \"$f\" ] && { echo \"########## $f\"; cat \"$f\"; echo; }; done"),
    ("users", "ssh_authorized_keys.txt",
        "for f in /root/.ssh/authorized_keys* /home/*/.ssh/authorized_keys*; do [ -f \"$f\" ] && { echo \"### $f\"; cat \"$f\"; }; done"),
    // --- processes / persistence ---
    ("processes", "ps_tree.txt", "ps auxwwf"),
    ("processes", "ps_detailed.txt", "ps -eo pid,ppid,user,lstart,etime,stat,cmd --sort=start_time"),
    ("processes", "proc_exe_cwd.txt", "for p in /proc/[0-9]*; do printf '%s exe=%s cwd=%s\\n' \"${p#/proc/}\" \"$(readlink $p/exe)\" \"$(readlink $p/cwd)\"; done"),
    ("processes", "open_files.txt", "lsof -nP 2>/dev/null"),
    ("processes", "systemd_units.txt", "systemctl list-units --all --no-pager 2>/dev/null; echo; systemctl list-unit-files --no-pager 2>/dev/null"),
    ("processes", "systemd_timers.txt", "systemctl list-timers --all --no-pager 2>/dev/null"),
    ("processes", "crontabs.txt",
        "for u in $(cut -d: -f1 /etc/passwd); do c=$(crontab -l -u \"$u\" 2>/dev/null) && printf '### crontab of %s\\n%s\\n\\n' \"$u\" \"$c\"; done; \
         echo '### /etc/crontab'; cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null"),
    ("processes", "docker.txt", "command -v docker >/dev/null && { docker ps -a; docker images; }"),
    // --- network ---
    ("network", "interfaces.txt", "ip addr; echo; ip route; echo; ip neigh"),
    ("network", "sockets.txt", "ss -tulpan 2>/dev/null || netstat -tulpan"),
    ("network", "connections.txt", "ss -tanp 2>/dev/null || netstat -tanp"),
    ("network", "firewall.txt", "iptables-save 2>/dev/null; echo; ip6tables-save 2>/dev/null; echo; nft list ruleset 2>/dev/null"),
    ("network", "dns_hosts.txt", "cat /etc/hosts; echo; cat /etc/resolv.conf"),
    // --- files ---
    ("files", "suid_sgid.txt", "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f -exec ls -la {} + 2>/dev/null"),
    ("files", "tmp_listing.txt", "ls -laR /tmp /var/tmp /dev/shm 2>/dev/null"),
    ("files", "capabilities.txt", "getcap -r / 2>/dev/null"),
];

/// (archive name, remote script writing a tar.gz to stdout). Paths are relative to /.
const ARCHIVES: &[(&str, &str)] = &[
    ("var_log.tar.gz", "cd / && tar -czf - --ignore-failed-read var/log"),
    ("etc.tar.gz", "cd / && tar -czf - --ignore-failed-read etc"),
    ("user_artifacts.tar.gz",
        "cd / && tar -czf - --ignore-failed-read --exclude='*/.cache' \
         root/.[!.]* home/*/.[!.]* var/spool/cron tmp var/tmp dev/shm 2>/dev/null"),
];
const WEB_ARCHIVE: (&str, &str) =
    ("web_roots.tar.gz", "cd / && tar -czf - --ignore-failed-read var/www srv 2>/dev/null");

struct Ssh {
    target: String,
    port: String,
    socket: PathBuf,
    known_hosts: PathBuf,
    identity: Option<String>,
    sudo: Sudo,
}

/// How root is reached on the victim.
enum Sudo {
    /// logged in as root
    None,
    /// `sudo -n` (NOPASSWD)
    NoPassword,
    /// `sudo -S`, the password is written to the remote command's stdin
    Password(String),
}

impl Ssh {
    fn command(&self) -> Command {
        let mut c = Command::new("ssh");
        c.arg("-S").arg(&self.socket).args(["-p", &self.port]);
        c.arg("-o").arg(format!("UserKnownHostsFile={}", self.known_hosts.display()));
        c.args(["-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR"]);
        if let Some(id) = &self.identity {
            c.args(["-i", id]);
        }
        c
    }

    /// Open the master connection; this is where the password is asked, once.
    fn connect(&self) -> io::Result<()> {
        let status = self
            .command()
            .args(["-M", "-f", "-N", "-o", "ControlPersist=1800", "-o", "ServerAliveInterval=30"])
            .arg(&self.target)
            .status()?;
        if status.success() { Ok(()) } else { Err(io::Error::other("SSH connection failed")) }
    }

    fn disconnect(&self) {
        let _ = self.command().args(["-O", "exit"]).arg(&self.target).stderr(Stdio::null()).status();
    }

    fn remote(&self, script: &str) -> String {
        let quoted = format!("'{}'", script.replace('\'', r"'\''"));
        match self.sudo {
            Sudo::None => format!("sh -c {quoted}"),
            Sudo::NoPassword => format!("sudo -n sh -c {quoted}"),
            // -p '': no prompt text mixed into the output; -k: always read the password,
            // so a cached sudo ticket can't make it pass the password on to the script
            Sudo::Password(_) => format!("sudo -S -k -p '' sh -c {quoted}"),
        }
    }

    /// Run `script` on the victim as root.
    fn run(&self, script: &str, stdout: Stdio, stderr: Stdio) -> io::Result<(ExitStatus, Vec<u8>)> {
        let password = match &self.sudo {
            Sudo::Password(p) => Some(p),
            _ => None,
        };
        let mut child = self
            .command()
            .arg(&self.target)
            .arg(self.remote(script))
            .stdin(if password.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(stdout)
            .stderr(stderr)
            .spawn()?;
        if let (Some(password), Some(mut stdin)) = (password, child.stdin.take()) {
            let _ = writeln!(stdin, "{password}"); // dropping stdin closes it
        }
        let out = child.wait_with_output()?;
        Ok((out.status, out.stdout))
    }

    fn output(&self, script: &str) -> io::Result<String> {
        let (_, stdout) = self.run(script, Stdio::piped(), Stdio::null())?;
        Ok(String::from_utf8_lossy(&stdout).trim().to_string())
    }

    /// Run `script` on the victim, streaming stdout into `out` and stderr into `errors`.
    fn to_file(&self, script: &str, out: &Path, errors: &mut File) -> io::Result<bool> {
        writeln!(errors, "===== {} ({}) =====", out.display(), now_human())?;
        let (status, _) = self.run(script, File::create(out)?.into(), errors.try_clone()?.into())?;
        Ok(status.success())
    }

    /// Make sure every step runs as root: directly, via passwordless sudo, or by asking
    /// for the sudo password.
    fn become_root(&mut self) -> io::Result<()> {
        let uid = self.output("id -u")?;
        if uid == "0" {
            return Ok(());
        }
        self.sudo = Sudo::NoPassword;
        if self.output("id -u")? == "0" {
            println!("[*] using passwordless sudo on the victim");
            return Ok(());
        }
        let user = self.target.split('@').next().unwrap_or("user").to_string();
        for attempt in 1..=SUDO_TRIES {
            let password = prompt_password(&format!("[sudo] password for {user} on the victim"))?;
            self.sudo = Sudo::Password(password);
            if self.output("id -u")? == "0" {
                println!("[*] using sudo on the victim");
                return Ok(());
            }
            eprintln!("    sudo refused ({attempt}/{SUDO_TRIES}): wrong password, or {user} may not use sudo");
        }
        Err(io::Error::other(format!(
            "could not become root as {user} (uid={uid}); log in as root or use a user in the sudo group"
        )))
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("[!] {e}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    if !which("ssh") {
        return Err(io::Error::other("'ssh' not found (apt install openssh-client)"));
    }
    let user = invoking_user()?;
    let root = log_root(&user);
    fs::create_dir_all(&root)?;

    println!("=== CTF-Logger: victim log collector ===  logs go to {}\n", root.display());
    let last_challenge = newest_subdir(&root);
    let default_name = last_challenge.as_ref().map(|p| p.file_name().unwrap().to_string_lossy().into_owned());
    let challenge = sanitize(&prompt("Challenge name", default_name.as_deref())?);
    let default_ip = target_ip_of(&root.join(&challenge));
    let ip = prompt_ip("Victim IP address", default_ip.as_deref())?;
    let ssh_user = prompt("SSH user (root, or a user that can sudo)", Some("root"))?;
    let port = prompt("SSH port", Some("22"))?;
    let identity = prompt("SSH private key file (- = log in with password)", Some("-"))?;
    let minutes = prompt("List files modified in the last N minutes", Some("240"))?
        .parse::<u32>()
        .unwrap_or(240);
    let with_web = prompt_yes_no("Also archive web roots (/var/www, /srv)?", true)?;

    let out_dir = root
        .join(&challenge)
        .join(format!("victim_{}_{}", ip.to_string().replace(':', "_"), timestamp()));
    fs::create_dir_all(out_dir.join("archives"))?;

    let mut ssh = Ssh {
        target: format!("{ssh_user}@{ip}"),
        port,
        socket: std::env::temp_dir().join(format!("ctf-ssh-{}.sock", std::process::id())),
        known_hosts: out_dir.join("known_hosts"),
        identity: (identity != "-").then_some(identity),
        sudo: Sudo::None,
    };

    println!("\n[*] connecting to {} ...", ssh.target);
    ssh.connect()?;
    let result = collect(&mut ssh, &out_dir, minutes, with_web);
    ssh.disconnect();
    let _ = fs::remove_file(&ssh.socket);
    if is_root() {
        chown_recursive(&root.join(&challenge), user.uid, user.gid)?;
    }
    result?;
    println!("\nSaved in {}", out_dir.display());
    Ok(())
}

fn collect(ssh: &mut Ssh, out_dir: &Path, minutes: u32, with_web: bool) -> io::Result<()> {
    ssh.become_root()?;
    let hostname = ssh.output("uname -n")?;
    println!("[*] root on {hostname} - collecting\n");

    let mut errors = OpenOptions::new().create(true).append(true).open(out_dir.join("errors.log"))?;
    let mut summary = File::create(out_dir.join("summary.txt"))?;
    writeln!(summary, "Victim:     {} ({hostname})", ssh.target)?;
    let via = match ssh.sudo {
        Sudo::None => "root login",
        Sudo::NoPassword => "sudo (no password)",
        Sudo::Password(_) => "sudo (password)",
    };
    writeln!(summary, "Root via:   {via}")?;
    writeln!(summary, "Started:    {}\n", now_human())?;

    let recent = format!(
        "find / -xdev \\( -path /proc -o -path /sys -o -path /run \\) -prune -o -type f -mmin -{minutes} \
         -printf '%TY-%Tm-%Td %TT  %u:%g  %m  %10s  %p\\n' 2>/dev/null | sort"
    );
    let recent_name = format!("modified_last_{minutes}min.txt");
    let mut jobs: Vec<(String, String, String)> = COMMANDS
        .iter()
        .map(|(d, f, s)| (d.to_string(), f.to_string(), s.to_string()))
        .collect();
    jobs.push(("files".into(), recent_name, recent));
    let mut archives: Vec<(&str, &str)> = ARCHIVES.to_vec();
    if with_web {
        archives.push(WEB_ARCHIVE);
    }
    for (name, script) in archives {
        jobs.push(("archives".into(), name.to_string(), script.to_string()));
    }

    let total = jobs.len();
    for (n, (dir, file, script)) in jobs.iter().enumerate() {
        fs::create_dir_all(out_dir.join(dir))?;
        let path = out_dir.join(dir).join(file);
        print!("[{:>2}/{total}] {dir}/{file} ... ", n + 1);
        io::stdout().flush()?;
        let ok = ssh.to_file(script, &path, &mut errors)?;
        let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        // tar / grep-style commands exit non-zero on harmless warnings; size tells more.
        let state = if size > 0 { "ok" } else if ok { "empty" } else { "failed" };
        println!("{state} ({})", human_size(size));
        writeln!(summary, "{state:<7} {:>10}  {dir}/{file}", human_size(size))?;
    }
    writeln!(summary, "\nFinished:   {}", now_human())?;

    // Hash the archives as downloaded, before anything is unpacked.
    write_manifest(out_dir)?;
    extract_archives(out_dir, &mut errors)?;
    Ok(())
}

/// Unpack every archive into `extracted/`, which then mirrors the victim's filesystem
/// (extracted/var/log, extracted/etc, extracted/home/...). Rotated `*.gz` logs are
/// decompressed next to the originals so every log can be read directly.
fn extract_archives(out_dir: &Path, errors: &mut File) -> io::Result<()> {
    let dest = out_dir.join("extracted");
    fs::create_dir_all(&dest)?;
    println!("\n[*] extracting archives into {}", dest.display());
    for entry in fs::read_dir(out_dir.join("archives"))?.filter_map(Result::ok) {
        let archive = entry.path();
        if fs::metadata(&archive).map(|m| m.len()).unwrap_or(0) == 0 {
            continue;
        }
        writeln!(errors, "===== extract {} ({}) =====", archive.display(), now_human())?;
        // The archive comes from the victim: GNU tar strips leading '/' and refuses '..'
        // members; never restore its owners or device files.
        let status = Command::new("tar")
            .args(["-xzf"])
            .arg(&archive)
            .arg("-C")
            .arg(&dest)
            .args(["--no-same-owner", "--no-same-permissions", "--exclude=dev/*"])
            .stdout(Stdio::null())
            .stderr(errors.try_clone()?)
            .status()?;
        let name = archive.file_name().unwrap().to_string_lossy().into_owned();
        // tar exits non-zero on harmless warnings (sockets, changed files); see errors.log
        println!("    {name}: {}", if status.success() { "ok" } else { "extracted with warnings (errors.log)" });
    }
    let logs = dest.join("var").join("log");
    if logs.is_dir() {
        let _ = Command::new("find")
            .arg(&logs)
            .args(["-type", "f", "-name", "*.gz", "-exec", "gunzip", "-k", "-f", "{}", "+"])
            .stderr(errors.try_clone()?)
            .status();
        println!("    rotated logs (*.gz) in var/log decompressed");
    }
    Ok(())
}

/// SHA-256 of every collected file (not of the extracted copies), for evidence integrity.
fn write_manifest(dir: &Path) -> io::Result<()> {
    let out = Command::new("sh")
        .args([
            "-c",
            "find . -path ./extracted -prune -o -type f ! -name MANIFEST.sha256 -exec sha256sum {} + | sort -k2",
        ])
        .current_dir(dir)
        .output()?;
    fs::write(dir.join("MANIFEST.sha256"), out.stdout)
}

/// Target IP recorded by the newest ctf-logger session of this challenge, if any.
fn target_ip_of(challenge_dir: &Path) -> Option<String> {
    let mut sessions: Vec<PathBuf> = fs::read_dir(challenge_dir)
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.join("session_info.txt").is_file())
        .collect();
    sessions.sort();
    let info = fs::read_to_string(sessions.last()?.join("session_info.txt")).ok()?;
    info.lines()
        .find_map(|l| l.strip_prefix("Target IP:"))
        .map(|ip| ip.trim().to_string())
}
