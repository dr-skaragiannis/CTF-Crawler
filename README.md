# ctf-logger

Two tools for recording a CTF attack end to end, for your own lab or competition boxes.

| Binary | Runs on | Does |
|---|---|---|
| `ctf-logger` | Kali (attacker), as root | Live pcap of **every** interface, every terminal's commands **and** output |
| `ctf-victim-logs` | Kali, any user | Pulls logs and forensic state from the **victim** over SSH (as root) |

## Build (on Kali)

```bash
sudo apt install -y cargo tcpdump bsdutils openssh-client
cargo build --release
sudo install -m 755 target/release/ctf-logger target/release/ctf-victim-logs /usr/local/bin/
```

## 1. Attacker side: `sudo ctf-logger`

Asks for the **challenge name** and the **target IP**, then records live to
`/home/<you>/CTF-Logs/<challenge>/<timestamp>/` until you press **Ctrl+C**:

```
pcap/eth0.pcap, pcap/lo.pcap, pcap/tun0.pcap ...  one tcpdump per interface
pcap/target_<ip>.pcap                             only traffic to/from the target (any interface)
terminals/<time>_<user>_<pid>.typescript          full terminal recording (input + output)
terminals/<...>.timing                            replay: scriptreplay -t X.timing X.typescript
terminals/<...>.txt                               clean text version (written when you stop)
commands.log                                      time, user@host, terminal, cwd, exit code, command
session_info.txt, events.log, tcpdump.log
```

- Interfaces that appear later (e.g. `tun0` when you start the VPN) are picked up within
  a second; if an interface goes down and comes back, a `.part2.pcap` is started.
- pcaps are written with `-U`, so you can open them in Wireshark while the session runs.
- **Only terminals opened after starting the logger are recorded.** A small hook is added
  to `~/.bashrc`/`~/.zshrc` of your user and of root (Kali's default shell is zsh, so both
  are supported). It does nothing when no session is running.
- `sudo su` / `sudo -i` inside a recorded terminal opens a nested recording as root, so
  root's commands are logged too.
- Remove the hooks with `sudo ctf-logger --uninstall`.

## 2. Victim side: `ctf-victim-logs`

Once you have root SSH access on the victim (as root, or a user with passwordless sudo):

```bash
ctf-victim-logs
```

It asks for the challenge (defaults to the latest one), the victim IP (defaults to the
target IP of the latest session), SSH user, port and optional key. You enter the password
once; one SSH master connection is reused for everything. Output goes to
`CTF-Logs/<challenge>/victim_<ip>_<timestamp>/`:

- `archives/` - `var_log.tar.gz`, `etc.tar.gz`, `user_artifacts.tar.gz` (shell histories,
  `.ssh`, cron spools, `/tmp`, `/var/tmp`, `/dev/shm`), optional `web_roots.tar.gz`
- `logs/` - full journal, kernel and SSH journal, dmesg, auditd reports
- `users/` - passwd/shadow/sudoers, `last`/`lastb`/`lastlog`, who, all shell histories, authorized_keys
- `processes/` - process tree, exe/cwd of every PID, open files, systemd units/timers, crontabs, docker
- `network/` - addresses, routes, listening sockets, connections, firewall rules, hosts/DNS
- `files/` - SUID/SGID, capabilities, `/tmp` listing, files modified in the last N minutes
- `summary.txt`, `errors.log`, `MANIFEST.sha256` (hashes of everything), `known_hosts`
