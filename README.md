# 🛡️ CyberSentinel — ML-Based Network Intrusion Detection & Prevention

CyberSentinel watches the network traffic of a Windows PC, decides whether it is an
attack, blocks the attacker with Windows Firewall, and reports everything to a web
dashboard with a plain-English explanation of each attack.

Detection uses two methods together:

- **A machine-learning model** — a Random Forest trained on the CICIDS2017 dataset.
  It recognises **DoS, DDoS, PortScan, BruteForce and Botnet** from 19 measurements of
  each network connection (flow).
- **Rate rules** — instant counters that catch floods: **SYN Flood, ICMP Flood and Port
  Scan**.

---

## How it works

```
 Network packets
       │  Scapy + Npcap capture (both directions)
       ▼
 Flow tracker ──► 19 CICIDS2017 features per connection ──► Random Forest model
       │                                                        │
       └──► Rate rules (SYN flood, port scan, ICMP flood)       │
                         │                                      │
                         ▼                                      ▼
                    Decision: block, alert, or ignore
                         │
          ┌──────────────┼──────────────────────┐
          ▼              ▼                      ▼
   Windows Firewall   Firestore (cloud)     Groq AI explanation
   rule (netsh)          │                  (offline text if unavailable)
                         ▼
             React dashboard (live, login required)
```

### When does it block?

| What happened | Result |
|---|---|
| A rate rule fired | **Blocked** immediately |
| Model says attack with ≥ 90% confidence, 3 such connections from one IP within 10 s | **Blocked** |
| Model says attack with 70–90% confidence | **Alert only** (shown, not blocked) |
| Model says attack with < 70% confidence | **Ignored** — treated as normal traffic to avoid false alarms |

Never blocked: this PC's own addresses, the router (gateway), DNS servers and the
networks listed in `python-engine/config.py`.

---

## Repository layout

```
python-engine/          Detection engine (runs on the protected Windows PC)
  main.py               Entry point: capture → flows → model + rules → decisions
  sniffer.py            Packet capture
  feature_extractor.py  Flow tracker and the 19 CICIDS2017 features
  classifier.py         Loads models/model_v1.pkl and classifies flows
  rules.py              SYN flood, port scan and ICMP flood rules
  detector.py           Decision table, confidence thresholds, alert throttling
  blocker.py            Windows Firewall blocking and unblocking
  firebase_client.py    Firestore writes and remote unblock commands
  ai.py                 Groq explanations with an offline fallback
  config.py             All settings (thresholds, detect-only default, never-block list)
  simulate_attack.py    One-laptop attack simulator for demos
  replay.py             Offline replay through the real model; exports the demo file
  tools/                manage_users.py, seed_firestore.py, check_rules.py
  tests/                Automated tests (pytest)

frontend/               React 19 + Vite dashboard
  src/pages/            Landing, Login, Dashboard, Threats, Topology, AI Analyst, Settings, Users, Audit log
  public/demo/          replay.json — recorded detections played by the public demo
  api/chat.js           Server function for the AI Analyst chat (Vercel)

training/               CICIDS2017 notebook, model report, verify_model.py
firestore.rules         Database access rules (admin / viewer roles)
docs/                   SRS, algorithm design and part-wise documentation
```

---

## Setup

**Requirements:** Windows 10/11, [Npcap](https://npcap.com/#download) (tick *WinPcap
API-compatible mode*), Python 3.10+ (Miniconda recommended), Node.js 18+.

### 1. Engine

```powershell
cd python-engine
pip install -r requirements.txt
```

Put these files in `python-engine/` (they are secret and never committed):

- `serviceAccountKey.json` — Firebase console → Project settings → Service accounts → Generate new private key
- `.env` — copy `.env.example` and add your `GROQ_API_KEY` (optional: without it the offline explanations are used)

### 2. Dashboard

```powershell
cd frontend
npm install
```

Copy `frontend/.env.example` to `frontend/.env` and fill in the six `VITE_FIREBASE_…`
values from Firebase console → Project settings → Your apps. The landing page and demo
work without them; login and the live dashboard need them.

### 3. Accounts

There is no public sign-up. Create users and set roles with:

```powershell
python python-engine/tools/manage_users.py add someone@example.com admin    # or viewer
python python-engine/tools/manage_users.py list
```

`add` prints a link where the person chooses their own password. Forgotten passwords:
use **Forgot password?** on the login page.

---

## Running

Open **two terminals**.

```powershell
# Terminal 1 — as Administrator
cd python-engine
python main.py               # detect-only: reports attacks, never touches the firewall
python main.py --block       # also blocks attackers with Windows Firewall
```

```powershell
# Terminal 2
cd frontend
npm run dev                  # http://localhost:5173
```

| Page | What it shows | Login |
|---|---|---|
| `/` | Landing page | No |
| `/demo` | Replay of 84 recorded detections from the real model | No |
| `/login` → `/app` | Live dashboard from Firestore | Yes |
| `/app/users`, `/app/audit` | Manage users, audit log of blocks and unblocks | Admin |

Dashboard tabs: **Dashboard** (counters, protocol chart, attack graph, threat log),
**Threats** (filterable log), **Topology** (full-screen attack graph), **AI Analyst**
(chat with Groq; `npm run dev` serves `/api/chat` locally using `GROQ_API_KEY` from
`python-engine/.env`), **Settings** (model facts and limitations). The live dashboard
shows detections from the last hour, 24 hours (default), 7 days or all time; the counters
cover the engine's current run.
**Explain** on any row shows severity, what happened, how the attack works and what to do.

---

## Demonstrating attacks

### On one laptop

With the engine running (as Administrator), in another Administrator terminal:

```powershell
cd python-engine
python simulate_attack.py              # port scan, SYN flood and ICMP flood
python simulate_attack.py portscan     # or just one of them
```

The fake attackers use reserved documentation addresses (198.51.100.x) that never
exist on a real network. Detections appear on the dashboard within seconds.

### With two laptops

Put both on a network you control (a phone hotspot works; avoid college networks).
Start the engine with `--block` on the protected PC and note its IP from `ipconfig`.

**Attacker on Windows** — copy `python-engine/simulate_attack.py`, install Python,
`pip install scapy` and Npcap, then in an Administrator terminal:

```powershell
python simulate_attack.py --target <protected-pc-ip>
```

The packets carry the attacker's real address, so the protected PC blocks that laptop;
unblock it from the dashboard afterwards.

**Attacker on Kali Linux** (or any machine with these tools):

| Attack | Command | Detected as |
|---|---|---|
| Port scan | `nmap -sS -p 1-1000 <target-ip>` | PortScan (rule) |
| SYN flood | `sudo hping3 -S -p 80 --flood <target-ip>` (a few seconds) | SynFlood (rule) |
| ICMP flood | `sudo hping3 --icmp --flood <target-ip>` | IcmpFlood (rule) |
| Brute force | `hydra -l test -P passwords.txt ssh://<target-ip>` (target runs OpenSSH Server) | BruteForce (model) |

### Removing blocks

Click **Unblock** on the dashboard (admins), or in an Administrator PowerShell:

```powershell
Remove-NetFirewallRule -DisplayName 'CyberSentinel Block *'
```

---

## Model

Random Forest (`python-engine/models/model_v1.pkl`), trained on CICIDS2017
(738,715 training and 184,679 test flows). Full report: `training/reports/model_v1.md`.

| Class | Precision | Recall |
|---|---|---|
| Benign | 0.9945 | 0.9976 |
| Botnet | 0.8788 | 0.5964 |
| BruteForce | 0.9989 | 0.9721 |
| DDoS | 0.9994 | 0.9988 |
| DoS | 0.9962 | 0.9920 |
| PortScan | 0.9966 | 0.9989 |

Test accuracy **99.56%**, macro F1 **0.947**. Check the model independently with
`python training/verify_model.py`.

## Tests

```powershell
cd python-engine
python -m pytest -q
```

## Known limitations

- Botnet recall is about 60% (57% after the 70% alert threshold).
- Web attacks (SQL injection, XSS), Infiltration and Heartbleed are not detected.
- Scores come from the CICIDS2017 lab network; real traffic produces some false alarms,
  which the 70% threshold reduces.
- Windows and IPv4 only. Blocks stay until someone removes them.

## Acknowledgements

Dataset: CICIDS2017, Canadian Institute for Cybersecurity, University of New Brunswick.
