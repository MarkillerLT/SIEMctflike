# siem-ctf — Usage Manual

A toy classroom CTF that teaches **dictionary brute-force attacks** and
**SIEM-style event monitoring**. Students (attackers) try to brute-force a
**fake SSH login** from their own devices on the LAN; you (the host) watch every
login attempt live.

> There is **no real SSH server** here — just login logic and an SSH theme. All
> accounts are fake and live only in memory on your machine. Run this only in
> your own classroom, on your own network, as an authorized teaching exercise.

---

## 0. What's in the box

```
siem-ctf/
├── server/
│   ├── config.py      # ← tune the exercise here (accounts, passwords, flags, threshold, port)
│   └── main.py        # FastAPI + WebSocket server
├── clients/
│   ├── attacker.py    # attacker CLI (SSH-style login terminal)
│   ├── monitor.py     # host SIEM monitor CLI (live colored feed)
│   └── grade.py       # grading / report tool (per-attacker results table)
├── data/
│   ├── passwords.txt  # the shared wordlist / password library (dictionary)
│   ├── events.jsonl   # vulnerability/event log      (auto-generated)
│   └── defense.jsonl  # defense logbook / bitácora    (auto-generated)
├── run.sh             # helper launcher (setup / server / monitor / attack / grade / ip / reset)
├── requirements.txt
└── MANUAL.md
```

---

## Quick start with `run.sh`

`run.sh` wraps everything below so you don't have to remember the venv/uvicorn
commands. From the project root:

| Command | Does |
|---|---|
| `./run.sh setup` | one-time: create `.venv` and install requirements |
| `./run.sh server [port]` | start the server on `0.0.0.0` (auto-picks a free port; prints the LAN URL to share) |
| `./run.sh monitor` | launch the host SIEM monitor |
| `./run.sh attack [nick]` | launch an attacker CLI (default nick: `attacker`) |
| `./run.sh grade` | print the per-attacker results table (grading) |
| `./run.sh ip` | print `ws://<your-ip>:<port>/ws` for classmates |
| `./run.sh reset` | empty both logs for a fresh session |
| `./run.sh help` | show usage |

Typical classroom run — three terminals:

```bash
./run.sh server            # terminal 1 (also prints the URL classmates use)
./run.sh monitor           # terminal 2 — your live SIEM view
./run.sh attack alice      # terminal 3 — a test attacker
```

**Choosing the port.** By default the server tries `8000`, and if that's taken
it automatically falls back to the next free port (`8080`, `8081`, …) and prints
which one it bound. To force a specific port, pass it or set `PORT`:

```bash
./run.sh server 9000          # positional
PORT=9000 ./run.sh server     # env var (equivalent)
```

`monitor`, `attack`, and `ip` auto-discover the running server's port (the
server records it in `data/.runtime_port`), so you don't have to repeat it. You
can still point an attacker at another host explicitly with
`URL=ws://192.168.1.42:9000/ws ./run.sh attack bob`.

> `run.sh` needs the venv. Run `./run.sh setup` once first (or the manual setup
> in §1). Everything after this section is the longhand equivalent if you'd
> rather run the commands yourself.

---

## 1. One-time setup (Arch Linux)

Python 3 is already on Arch. You only need a virtual environment + the deps.

```bash
# system python / venv support (usually already present)
sudo pacman -S --needed python

cd ~/School/siem-ctf
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

That installs **FastAPI**, **Uvicorn**, and the **websockets** library (used by
the two CLI clients).

> **Cloning from GitHub?** The `.venv/` folder is intentionally **not** in the
> repo (a virtualenv hardcodes absolute paths to the machine that made it, so a
> committed one won't work elsewhere). `.gitignore` excludes it along with the
> Python caches and the generated logs. Just run `./run.sh setup` once after
> cloning to build your own `.venv` locally.

---

## 2. Run the server

From the project root, with the venv active:

```bash
source .venv/bin/activate          # if not already active
python -m server                   # binds 0.0.0.0, auto-picks a free port
# force a port:  PORT=9000 python -m server
```

Binding `0.0.0.0` exposes all interfaces so classmates on the LAN can reach you.
On startup the server prints the exact `ws://…` URL (with the chosen port) to
share. Sanity check in a browser or curl: `http://127.0.0.1:<port>/` returns the
service info and the three level names.

> Port selection lives in `server/config.py` (`DEFAULT_PORT` and the
> `PORT_CANDIDATES` fallback list). The `PORT` env var overrides both. The old
> `uvicorn server.main:app --port 8000` invocation still works if you want to
> pin everything by hand, but `python -m server` is what gives you the
> auto-fallback and the printed URL.

---

## 3. Run the host monitor (your live SIEM view)

In a second terminal (venv active):

```bash
python clients/monitor.py --url ws://127.0.0.1:8000/ws
```

You'll see a live feed. Each attempt is one line with a per-attacker counter:

- dim `try` — normal failed attempt
- yellow `SUSPECT` — attacker crossed the failed-attempt threshold
- red `LOCKED` / `ALERT` — account locked (fail2ban-style defense)
- green `SUCCESS` — someone cracked an account (shows which level)

As the host you normally watch `127.0.0.1` (your own machine).

---

## 4. Run an attacker (what students run)

In another terminal (venv active). Locally for testing:

```bash
python clients/attacker.py --url ws://127.0.0.1:8000/ws --nick alice
```

Students on the LAN point `--url` at **your** IP (see §6):

```bash
python clients/attacker.py --url ws://<your-ip>:8000/ws --nick bob
```

The client presents an **SSH-style login terminal**:

```
LOADING SSH
alice@Server.app
User: admin
Password: ******
Permission denied (publickey,password).
Password: ******
Welcome to admin@sshd.
FLAG: FLAG{admin_...}
```

- At `User:` type the account to attack (`admin`, `devops`, or `root`).
- At `Password:` type a guess (input is masked). Like real `sshd` you get a few
  tries before it drops back to the `User:` prompt.
- Crack an account and the terminal prints its **FLAG** — the student's proof /
  incentive. Type `quit` to disconnect.

Guessing one password at a time is slow on purpose: the whole point is to teach a
**dictionary / brute-force attack**. Students use the shared password library in
`data/passwords.txt` — trying entries by hand, or (better) writing their **own
script** that speaks the WebSocket protocol in §8 and loops over the wordlist.
The flag is only an incentive; the **grade report** (§7) and live monitor are the
real record of who got in.

---

## 5. The three levels (host reference)

Three fake SSH accounts, each with its own flag. The usernames, passwords, flags,
and per-level defense live in the `ACCOUNTS` dict at the top of
`server/config.py` — **this is your answer key, so edit it for your class** (and
see the heads-up in §9 about this file being visible in a public repo).

| Level  | User     | Where its password sits in `passwords.txt` | Defense        |
|--------|----------|--------------------------------------------|----------------|
| easy   | `admin`  | near the **top** → cracks almost instantly | none           |
| medium | `devops` | **deeper** in the list → takes many tries  | none           |
| hard   | `root`   | **deep** in the list                       | **lockout ON** |

What each level teaches (watch it on the monitor while a student attacks):

1. **easy** — the password is one of the first wordlist entries, so a dictionary
   loop cracks it almost immediately. The monitor shows a green `SUCCESS`.

2. **medium** — the password sits deeper, so it takes many tries. Watch the
   per-attacker counter climb and the event risk flip to `SUSPECT` once it passes
   the threshold.

3. **hard** — the correct password is deep in the list, but **lockout kicks in
   first**: after `FAIL_THRESHOLD` (default 5) failures the `root` account is
   **locked** (fail2ban-style). The monitor fires a red `ALERT` and a line is
   written to the **defense logbook**. Naive brute force is blocked — students
   must slow down or rethink. The lock lasts `LOCKOUT_SECONDS` (default 60).

### Tuning knobs (`server/config.py`)
- `FAIL_THRESHOLD` — failed attempts before an event is flagged suspicious / lockout triggers.
- `LOCKOUT_SECONDS` — how long the hard account stays locked.
- `ACCOUNTS` — usernames, passwords, flags, and whether `lockout` is on per level.
- Edit `data/passwords.txt` freely — one password per line. To make `medium`
  harder/easier, move its password further down / further up the file.

---

## 6. Connecting classmates over the LAN (Arch)

**Find your IP:**

```bash
ip addr            # look for your WiFi/Ethernet interface, e.g. 192.168.1.42
# or quickly:
ip route get 1.1.1.1 | awk '{print $7; exit}'
```

Students then connect with:

```bash
python clients/attacker.py --url ws://192.168.1.42:8000/ws --nick <their-name>
```

**Firewall:** if you run a firewall, allow the port. Examples:

```bash
# ufw
sudo ufw allow 8000/tcp
# firewalld
sudo firewall-cmd --add-port=8000/tcp
# nftables / iptables: open TCP 8000 inbound
```
(Many default Arch desktops run no firewall — then nothing to do.)

**WiFi client isolation caveat:** some school/campus/guest WiFi networks enable
"client isolation" (AP isolation), which blocks device-to-device traffic even on
the same SSID. If classmates can reach the internet but **not** your IP, that's
almost certainly the cause. **Fallback:** create a **phone hotspot**, have
everyone (including you) join it, then re-run `ip addr` to get your new hotspot
IP and share `ws://<that-ip>:8000/ws`.

---

## 7. The two logs (course material)

Both are **JSON Lines** (one JSON object per line) in `data/`:

- **`events.jsonl` — vulnerability / event log.** Every login attempt:
  `timestamp, attacker, username, password, result, risk (normal|suspicious),
  level (easy|medium|hard)`.

- **`defense.jsonl` — defense logbook (bitácora).** Defensive actions the system
  took, e.g. `account_locked` with the attacker, failed-attempt count, and lock
  duration.

Inspect them live while the class runs:

```bash
tail -f data/events.jsonl
tail -f data/defense.jsonl
# pretty-print with jq if installed:
tail -f data/events.jsonl | jq .
```

To start a fresh session, just empty them: `: > data/events.jsonl`.
State (counters, locks) lives in memory and resets when you restart the server.

### Grading the session (`grade.py`)

When the exercise is over, turn the event log into a scoreboard:

```bash
./run.sh grade
# or:  python clients/grade.py
# also export a spreadsheet:  python clients/grade.py --csv results.csv
```

It prints one row per attacker **per level** — the flag (only for levels they
actually cracked) and `Pass` / `not pass` — plus a `levels cleared` score:

```
ATTACKER  ACCOUNT  FLAG                     STATUS
alice     admin    FLAG{admin_...}          Pass
alice     devops   FLAG{devops_...}         Pass
alice     root     FLAG{null}               not pass

Score (levels cleared):
  alice     2/3
```

Because it's built from the **server-side event log**, a student can't fake a
success by pasting a flag — only a real cracked login counts. The flag is just
the in-game incentive.

---

## 8. Message protocol (for reference / a future frontend)

All messages are JSON with a `type` field.

**Client → server**
```json
{"type":"join","role":"attacker","nickname":"alice"}
{"type":"join","role":"host","nickname":"host-monitor"}
{"type":"login_attempt","username":"admin","password":"123456"}
```

**Server → attacker**
```json
{"type":"login_result","result":"incorrect","message":"Permission denied...","level":"easy"}
{"type":"login_result","result":"locked","message":"Account locked. Try again in 59s.","level":"hard"}
{"type":"login_result","result":"success","message":"...","flag":"FLAG{...}","level":"easy"}
```

**Server → host monitor**
```json
{"type":"new_event","event":{"timestamp":"...","attacker":"alice","username":"admin","password":"123456","result":"success","risk":"normal","level":"easy"}}
{"type":"alert","message":"SUSPICIOUS: 'alice' made 5 failed attempts on 'root' -> account LOCKED for 60s","event":{...},"defense":{...}}
```

A future web frontend can speak this exact protocol — no server changes needed.

---

## 9. Heads-up before you publish this to GitHub

This repo **is the answer key.** `server/config.py` contains the real passwords
and flags, and `data/passwords.txt` is the wordlist that includes them. Anyone
who reads a public repo can find every answer without attacking anything.

That's fine if you only hand students the `--url` and tell them to run the
attacker (most won't dig through the source). But if you want the challenge to
stay fair even for repo-readers, consider one of:

- Keep the public repo as the **engine**, and move the real
  `ACCOUNTS`/wordlist into a separate, **private** config you drop in only on the
  machine that runs the server (e.g. a git-ignored `server/secrets.py`).
- Or publish with placeholder passwords/flags and swap in the real ones locally
  right before class.

Ask me and I can wire up the git-ignored-secrets split for you.
