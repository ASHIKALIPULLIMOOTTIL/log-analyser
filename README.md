# SSH Log Analyser

A Java command-line tool that reads a Linux SSH authentication log (`/var/log/auth.log`) and reports **who is trying to break into the server**.

It detects:

| Alert | Severity | Rule |
|---|---|---|
| Possible break-in | CRITICAL | An IP failed to log in many times, then **succeeded** |
| Brute-force attack | HIGH | Many failed logins from one IP within a short time window |
| Username guessing | MEDIUM | One IP tried many different usernames |

No external libraries are needed. It uses only the Java standard library.

---

## Requirements

- Java 11 or newer (`java -version` to check)

## Run (one command)

```bash
./analyse.sh sample-logs/auth.log
```

This compiles the code (only when it has changed), prints the report, and then asks which IPs to block.

```bash
# Your own machine's log
./analyse.sh /var/log/auth.log

# Report only, no blocking question
./analyse.sh /var/log/auth.log --no-block

# Stricter rules: 10 failures within 30 seconds counts as brute-force
./analyse.sh sample-logs/auth.log --threshold 10 --window 30
```

> **Permission denied on `/var/log/auth.log`?** On Ubuntu the file is readable by the `adm` group, which the default user is in. If you get an error, use `sudo ./analyse.sh /var/log/auth.log`.
>
> **No `/var/log/auth.log` on your system?** Some systems keep SSH logs only in the journal. Export them first:
> `sudo journalctl -u ssh -u sshd > my-auth.log`

### Options

| Option | Default | Meaning |
|---|---|---|
| `--threshold N` | 5 | Failed logins that count as brute-force |
| `--window SECONDS` | 60 | Time window for the threshold |
| `--users N` | 5 | Distinct usernames from one IP that count as guessing |
| `--firewall NAME` | `ufw` | Firewall to use: `ufw` or `iptables` |
| `--allow IP,IP` | *(none)* | IPs that must never be offered for blocking |
| `--no-block` | *(off)* | Only show the report, don't ask about blocking |

---

## Blocking attackers

After the report, the tool shows a checklist:

```
BLOCK SUSPICIOUS IPs

  [x] 1. 192.0.2.77       CRITICAL  Possible break-in, Brute-force
  [x] 2. 203.0.113.45     HIGH      Brute-force
  [ ] 3. 198.51.100.23    MEDIUM    Username guessing

Block the checked [x] IPs?  y = yes, n = no, or type numbers to check/uncheck (e.g. 2 or 1,3):
```

- Type **numbers** (`2`, or `1,3`) to check or uncheck IPs. The list is shown again.
- Type **`y`** to block the checked IPs, or **`n`** to cancel without changing anything.
- HIGH and CRITICAL IPs start **checked**. MEDIUM IPs start **unchecked**.
- Blocking needs administrator rights, so `sudo` asks for your password when you press `y`.
- When it finishes, it prints the commands to **undo** each block.

Safety features:

- **Nothing is blocked without a `y`.** Answering `n`, or pressing Ctrl+D, leaves the firewall untouched.
- **Your own IPs are never offered.** `127.0.0.1`, `::1` and the IP you are connected from over SSH (read from `$SSH_CLIENT`) are left out automatically. Add more with `--allow`. Because `sudo` clears `$SSH_CLIENT`, run the tool **without** sudo when you can; it asks for sudo only for the blocking step.
- **Injection-safe.** IPs come from the log, and attackers control part of each log line (the username). Every IP is checked against a strict IPv4/IPv6 pattern, the parser always takes the *last* `from <IP> port` in a line (the one sshd writes), and firewall commands are started directly with `ProcessBuilder`, never through a shell.
- **ufw rules are inserted at the top** (`ufw insert 1`). A plain `ufw deny` is added after an existing `allow 22` rule and would have no effect.
- **Blocking the same IP twice is harmless.** iptables checks for an existing rule (`iptables -C`) first, and ufw skips duplicates itself.

> If you use ufw, check it is active with `sudo ufw status`. Rules do nothing while ufw is inactive. Before enabling it, run `sudo ufw allow ssh` so you don't lock yourself out.

---

## Example output

```
============================================================
  SSH LOG ANALYSIS REPORT
============================================================
File analysed      : sample-logs/auth.log
Total lines        : 35
Failed logins      : 27
Successful logins  : 2
Unique IPs seen    : 4

Top attacking IPs (by failed logins):
  203.0.113.45           13
  198.51.100.23           7
  192.0.2.77              6
  10.0.0.5                1

Most targeted usernames:
  root                   11
  ubuntu                  7
  admin                   2
  ...

ALERTS:
  [CRITICAL] 192.0.2.77       Possible break-in: 6 failed logins, then SUCCESSFUL login as 'ubuntu' at 2026-11-02T04:02:25
  [HIGH    ] 203.0.113.45     Brute-force: 13 failed logins in total, up to 11 within 60 seconds
  [HIGH    ] 192.0.2.77       Brute-force: 6 failed logins in total, up to 6 within 60 seconds
  [MEDIUM  ] 198.51.100.23    Username guessing: tried 7 different usernames (deploy, ftpuser, git, oracle, pi, ...)
============================================================
```

---

## How it works

```
auth.log ──► LogParser ──► List<LoginEvent> ──► Detector ──► List<Alert> ──► ReportPrinter
              (regex)       (time, user, IP,      (3 rules)                    (terminal report)
                             success/fail)
```

| File | What it does |
|---|---|
| `Main.java` | Reads command-line options and runs the pipeline |
| `LogParser.java` | Uses regular expressions to find `Failed password` / `Accepted password` lines and extract time, username and IP. Supports both the classic syslog timestamp (`Nov  2 03:14:07`) and the newer ISO format (`2026-11-02T03:14:07...`), and expands `message repeated N times` lines |
| `LoginEvent.java` | One parsed login attempt |
| `Detector.java` | The three detection rules. Brute-force uses a **sliding time window** to find the busiest period for each IP |
| `Alert.java` | One finding with a severity level |
| `ReportPrinter.java` | Counts and prints the final report |
| `Blocker.java` | Picks the IPs that can be blocked, validates them and runs the ufw or iptables commands |
| `BlockMenu.java` | The interactive yes/no checklist |
| `analyse.sh` | Compiles when needed and runs the tool in one command |

The IP addresses in the sample log come from ranges reserved for documentation (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), so they don't belong to real hosts.

---

## Ideas for future features

- [ ] Show the country of each attacking IP (MaxMind GeoLite2, free)
- [ ] Export the report as CSV or JSON
- [ ] Support Apache/Nginx web server logs (detect SQL injection and directory scanning)
- [x] Generate firewall rules for the worst attackers
- [ ] Temporary blocks that expire after a set time
- [ ] Show attacks per hour as a simple text chart
- [ ] Add JUnit tests for the parser and detector

## Disclaimer

For educational use and for analysing logs from systems you own or are authorised to monitor.
