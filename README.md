# CTF-Crawler

Two tools for recording a CTF attack end to end, for your own lab or competition boxes.

| Binary | Runs on | Does |
|---|---|---|
| `ctf-logger` | Kali (attacker), as root | Live pcap of **every** interface; every terminal's commands **with their output**; Firefox/Chrome TLS keys + history; all Burp Suite requests |
| `ctf-victim-logs` | Kali, any user | Pulls logs and forensic state from the **victim** over SSH (as root) |

## Build (on Kali)

```bash
sudo apt install -y cargo tcpdump bsdutils openssh-client python3
cargo build --release
sudo install -m 755 target/release/ctf-logger target/release/ctf-victim-logs /usr/local/bin/
```

## 1. Attacker side: `sudo ctf-logger`

Asks for the **challenge name** and the **target IP**, then records live to
`/home/<you>/CTF-Logs/<challenge>/<timestamp>/` until you press **Ctrl+C**.

### Terminals (bash and zsh)

Every terminal opened after the logger starts is recorded with `script`, and every
command is cut out with **its own output**:

```
================================================================================
[2026-10-30 17:02:06.793] kali@kali:/home/kali   (terminal 20261030_170200_kali_4242)
$ nmap -sV 10.10.10.5
--------------------------------------------------------------------------------
Starting Nmap 7.95 ...
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1
[exit 0 | 14.2 s]
```

| File | Contents |
|---|---|
| `terminal_output.log` | all commands of all terminals with their output, in time order (updated every 5 s) |
| `terminals/<id>.log` | the same, for one terminal |
| `terminals/<id>.txt` | the whole terminal as plain text (colours and redraws removed) |
| `terminals/<id>.typescript` + `.timing` | raw recording; replay with `scriptreplay -t X.timing X.typescript` |
| `commands.log` | one line per command: time, user@host, terminal, cwd, exit code, command |

- A hook is added to `~/.bashrc`/`~/.zshrc` of your user and of root (Kali's default shell
  is zsh). It does nothing when no session is running.
- `sudo su` / `sudo -i` in a recorded terminal opens a nested recording as root.
- Interactive tools (msfconsole, vim, less) appear as one block with everything they printed.

### Network

| File | Contents |
|---|---|
| `pcap/<iface>.pcap` | one tcpdump per interface; `tun0` etc. are picked up when they appear |
| `pcap/target_<ip>.pcap` | only traffic to/from the target, any interface |

pcaps are written with `-U`, so Wireshark can open them while the session runs.

### Firefox / Chrome / Chromium / Brave

| File | Contents |
|---|---|
| `browser/tls_keys.log` | TLS session keys, so Wireshark can **decrypt the HTTPS** in the pcaps |
| `browser/history.tsv` | every page visited (link/typed/form/redirect) and every download during the session |

- TLS keys are logged for browsers started **after** the logger, from the applications
  menu or from a recorded terminal. Close a browser that was already open and start it again.
- To decrypt in Wireshark: *Edit > Preferences > Protocols > TLS > (Pre)-Master-Secret log
  filename* = `browser/tls_keys.log`.
- History is exported every minute and when you stop (needs `python3`).

### Burp Suite (Community or Pro)

Load the extension **once** and it logs whenever a session runs:

1. Download the Jython standalone JAR (https://www.jython.org/download) and set it in
   Burp under *Settings > Extensions > Python environment*.
2. Run `sudo ctf-logger` once (it installs `/etc/ctf-logger/ctf_burp_logger.py`).
3. In Burp: *Extensions > Installed > Add*, type **Python**, file
   `/etc/ctf-logger/ctf_burp_logger.py`. Burp remembers it.

| File | Contents |
|---|---|
| `burp/burp_http.log` | every full request and response, from **every Burp tool** (Proxy, Repeater, Intruder, Scanner...) |
| `burp/burp_requests.tsv` | one line per request: time, tool, method, URL, status, sizes |

### Stopping and cleaning up

Ctrl+C stops the captures and writes the final transcripts and history. Terminals still
open keep writing their `.typescript`. `sudo ctf-logger --uninstall` removes the shell
hooks, the browser launcher overrides and `/etc/ctf-logger` (unload the Burp extension in Burp).

## 2. Victim side: `ctf-victim-logs`

Once you have SSH access to the victim as **root** or as **any user that can sudo**:

```bash
ctf-victim-logs
```

It asks for the challenge (defaults to the latest one), the victim IP (defaults to the
target IP of the latest session), SSH user, port and optional key. You enter the SSH
password once; one SSH master connection is reused for everything. If the user is not
root, passwordless sudo is tried first, otherwise you are asked for the sudo password
(hidden, 3 tries), which is passed to `sudo -S` for every step. Output goes to
`CTF-Logs/<challenge>/victim_<ip>_<timestamp>/`:

- `archives/` - `var_log.tar.gz`, `etc.tar.gz`, `user_artifacts.tar.gz` (shell histories,
  `.ssh`, cron spools, `/tmp`, `/var/tmp`, `/dev/shm`), optional `web_roots.tar.gz`
- `extracted/` - all archives unpacked, mirroring the victim (`extracted/var/log/auth.log`,
  `extracted/etc/...`, `extracted/home/...`); rotated `*.gz` logs are also decompressed
- `logs/` - full journal, kernel and SSH journal, dmesg, auditd reports
- `users/` - passwd/shadow/sudoers, `last`/`lastb`/`lastlog`, who, all shell histories, authorized_keys
- `processes/` - process tree, exe/cwd of every PID, open files, systemd units/timers, crontabs, docker
- `network/` - addresses, routes, listening sockets, connections, firewall rules, hosts/DNS
- `files/` - SUID/SGID, capabilities, `/tmp` listing, files modified in the last N minutes
- `summary.txt`, `errors.log`, `MANIFEST.sha256` (hashes of everything as downloaded), `known_hosts`
