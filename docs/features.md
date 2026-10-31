# CyberSentinel — Feature Catalogue

> A comprehensive enumeration of every current capability of the system, and a
> roadmap of potential future features with the technologies that could implement
> them.

---

## Table of Contents

1. [Current Features](#1-current-features)
   - 1.1 [Packet Capture & Flow Tracking](#11-packet-capture--flow-tracking)
   - 1.2 [Machine-Learning Detection](#12-machine-learning-detection)
   - 1.3 [Rule-Based Detection](#13-rule-based-detection)
   - 1.4 [Decision Engine & Correlation](#14-decision-engine--correlation)
   - 1.5 [Active Blocking (Windows Firewall)](#15-active-blocking-windows-firewall)
   - 1.6 [AI-Generated Explanations](#16-ai-generated-explanations)
   - 1.7 [Cloud Sync (Firestore)](#17-cloud-sync-firestore)
   - 1.8 [React Dashboard](#18-react-dashboard)
   - 1.9 [Role-Based Access Control](#19-role-based-access-control)
   - 1.10 [Audit Log](#110-audit-log)
   - 1.11 [Attack Simulation & Offline Replay](#111-attack-simulation--offline-replay)
   - 1.12 [Testing Infrastructure](#112-testing-infrastructure)
   - 1.13 [Admin Tooling](#113-admin-tooling)
2. [Known Limitations](#2-known-limitations)
3. [Potential Future Features](#3-potential-future-features)
   - 3.1 [Expanded ML Coverage](#31-expanded-ml-coverage)
   - 3.2 [Deep-Packet Inspection (Layer 7)](#32-deep-packet-inspection-layer-7)
   - 3.3 [Anomaly Detection (Unsupervised)](#33-anomaly-detection-unsupervised)
   - 3.4 [Real-Time Streaming Pipeline](#34-real-time-streaming-pipeline)
   - 3.5 [Multi-Host / Network-Wide Deployment](#35-multi-host--network-wide-deployment)
   - 3.6 [SIEM Integration & Alerting](#36-siem-integration--alerting)
   - 3.7 [Adaptive / Auto-Updating Model](#37-adaptive--auto-updating-model)
   - 3.8 [IPv6 Support](#38-ipv6-support)
   - 3.9 [Enhanced Dashboard & Visualisations](#39-enhanced-dashboard--visualisations)
   - 3.10 [Automated Threat Response Playbooks](#310-automated-threat-response-playbooks)
   - 3.11 [Mobile Companion App](#311-mobile-companion-app)
   - 3.12 [LLM-Powered Security Analyst Chat](#312-llm-powered-security-analyst-chat)
   - 3.13 [Cross-Platform Engine](#313-cross-platform-engine)
   - 3.14 [Threat Intelligence Feeds](#314-threat-intelligence-feeds)
   - 3.15 [Federated / Privacy-Preserving Learning](#315-federated--privacy-preserving-learning)

---

## 1. Current Features

### 1.1 Packet Capture & Flow Tracking

| Component | File | Description |
|---|---|---|
| **BPF-filtered capture** | `sniffer.py` | Scapy + Npcap captures IPv4 TCP/UDP/ICMP packets (BPF filter `ip and (tcp or udp or icmp)`); packets that are neither to nor from the local machine are then dropped in Python, keeping the pipeline narrow. Falls back to Scapy's Layer-3 raw socket when Npcap is absent. |
| **Packet parser** | `feature_extractor.py` | `parse_packet()` extracts headers, flags (SYN/ACK/FIN/RST), and the exact payload length calculation used by the CICIDS2017 dataset (including short-frame Ethernet padding) into a lightweight frozen `PacketInfo` dataclass. |
| **Bi-directional flow tracker** | `feature_extractor.py` | `FlowTracker` aggregates packets from both ends of a connection into a `Flow` object using a symmetric key. Closes flows on TCP FIN/RST, after an idle timeout, after a maximum duration, or by evicting the oldest flow when the table is full. |
| **19-feature CICIDS2017 vector** | `feature_extractor.py` | `build_features()` computes the 19 statistical flow features the model was trained on: duration, packet counts, byte totals, max/mean payload lengths, flow bytes/s, packets/s, inter-arrival time statistics, forward/backward IAT means, and down/up ratio. |
| **Producer/consumer threading** | `main.py` | Three daemon threads (Flow Worker, Flow Sweeper, Detection Worker) communicate via bounded queues, keeping packet capture non-blocking. Dropped counts are logged when the engine falls behind. |

---

### 1.2 Machine-Learning Detection

| Component | File | Description |
|---|---|---|
| **Random Forest classifier** | `classifier.py` | `ThreatClassifier` wraps `model_v1.pkl` — a scikit-learn `Pipeline` (median imputer + 100-tree Random Forest, max depth 20) trained on 738,715 CICIDS2017 flows (923,394 flows in total, 80/20 train/test split). |
| **Detected attack classes** | — | **DoS**, **DDoS**, **PortScan**, **BruteForce**, **Botnet** (plus a Benign class). |
| **Per-class confidence scores** | `classifier.py` | `predict_proba` gives a probability for each class; the max probability is used as the confidence for the decision table. |
| **Detection evidence** | `classifier.py` | Up to 3 features whose values are furthest above their normal level (the 99th percentile of benign traffic) are attached to each detection as structured evidence for the dashboard and the AI explanation. |
| **Batch classification** | `main.py` | Flows are classified in batches for throughput; results are still processed in arrival order with rule hits interleaved. |
| **Model versioning** | `config.py` | `ACTIVE_MODEL` selects the `.pkl` and `.meta.json` files; swapping the model requires only a config change. |
| **Test accuracy** | — | 99.56% on 184,679 held-out CICIDS2017 test flows; macro F1 0.947. |

---

### 1.3 Rule-Based Detection

Independently of the flow-level ML model, a **rate-based rule engine** watches raw packets from each remote source using short sliding windows:

| Rule | Trigger | Evidence |
|---|---|---|
| **SynFlood** | More than *N* TCP SYN-without-ACK packets from one IP inside a window (configurable) | Count of SYNs in the window |
| **PortScan** | More than *N* distinct destination ports touched (via TCP SYN or UDP new-flow) from one IP in a window | Number of distinct ports |
| **IcmpFlood** | More than *N* ICMP packets from one IP in a window | Count of ICMP packets |

Rules fire immediately (no flow needs to close first), have a per-source cooldown to suppress repetition, and prune stale sources automatically.

---

### 1.4 Decision Engine & Correlation

| Feature | File | Description |
|---|---|---|
| **Decision table** | `detector.py` | Combines rule hits and model verdicts for the same remote IP within a correlation window (`CORRELATION_WINDOW`). Trigger is `rule`, `model`, or `both`; action is `blocked`, `alert_only`, `detect_only`, or `whitelisted`. |
| **Confidence thresholds** | `config.py` | Verdicts below `ALERT_CONFIDENCE` (70%) are silently ignored; verdicts at or above `BLOCK_CONFIDENCE` (90%) trigger a block once `MODEL_BLOCK_MIN_FLOWS` (3) attack flows from the same source arrive within `CORRELATION_WINDOW` (10 s). |
| **Alert throttling** | `detector.py` | At most one record per (IP, label) pair every `ALERT_THROTTLE_SECONDS`. Held-back packets counts are accumulated and merged into the next emitted record. |
| **IP whitelist** | `blocker.py` | The local machine, default gateway, DNS servers, loopback, multicast, and configurable CIDR ranges are never blocked, even if the model/rules fire. |
| **Detect-only mode** | `main.py` | `--detect-only` flag: detections are recorded and reported, but the firewall is never touched. Default mode for first-time users. |

---

### 1.5 Active Blocking (Windows Firewall)

| Feature | File | Description |
|---|---|---|
| **Inbound block rules** | `blocker.py` | `block_ip()` calls `netsh advfirewall firewall add rule` to create an inbound block for the attacker's IP, named `CyberSentinel Block <ip>`. |
| **Duplicate detection** | `blocker.py` | An in-memory set and a `netsh show rule` check prevent duplicate firewall rules across engine restarts. |
| **Rule survival across restarts** | `blocker.py` | `load_existing_rules()` at startup reads all existing `CyberSentinel Block *` rules back into memory. |
| **Remote unblock** | `blocker.py` | `unblock_ip()` calls `netsh ... delete rule` and removes the IP from the in-memory set. Triggered by the dashboard's **Unblock** button via Firestore commands. |
| **Bulk cleanup** | `blocker.py` | `unblock_all()` removes every CyberSentinel rule with a single PowerShell `Remove-NetFirewallRule` call. |

---

### 1.6 AI-Generated Explanations

| Feature | File | Description |
|---|---|---|
| **Groq LLM explanations** | `ai.py` | When `GROQ_API_KEY` and `GROQ_MODEL` are set, the `Explainer` sends anonymised threat metadata (label, confidence, evidence, action — never packet contents) to the Groq Chat Completions API and parses a JSON reply with four fields: `severity`, `summary`, `mechanism`, `recommendation`. |
| **Offline fallback** | `ai.py` | Hardcoded plain-English texts for every known label are used when Groq is unavailable, rate-limited, or returns an unexpected response. Detection is never delayed. |
| **Rate limiting** | `ai.py` | At most `AI_MAX_PER_MINUTE` API calls per minute; calls for the same (label, IP) pair within `AI_REUSE_SECONDS` reuse the cached explanation. |
| **Background delivery** | `ai.py` | Explanations are fetched on a dedicated thread and written back to Firestore as a sub-document update; the detection pipeline is unaffected. |
| **Severity levels** | `ai.py` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` — validated before storage. |
| **AI Analyst chat** | `frontend/api/chat.js` | A Vercel serverless function proxies chat messages to Groq with a security-analyst system prompt, enabling a freeform Q&A tab on the dashboard. |

---

### 1.7 Cloud Sync (Firestore)

| Collection | Writer | Reader | Purpose |
|---|---|---|---|
| `threats/{id}` | Engine (Admin SDK) | All signed-in users | One document per detection event with all fields + explanation sub-document |
| `stats/live` | Engine | All signed-in users | Rolling counters (packets, flows, attacks, blocked IPs, threat level, model version, engine heartbeat) |
| `commands/{id}` | Admin dashboard | Engine | Unblock requests; engine polls via Firestore real-time listener and sets `status` to `done` or `failed` |
| `audit/{id}` | Engine | Admins | Immutable log of every block and unblock event with actor email and timestamp |
| `users/{uid}` | Admin dashboard | Admin + self | User profile and role |

All Firestore writes are non-blocking: they run on a `CloudWriter` background thread via a bounded job queue. The engine continues without the cloud when no `serviceAccountKey.json` is present.

---

### 1.8 React Dashboard

Built with **React 19 + TypeScript + Vite + Tailwind CSS + React Router**.

| Page / Tab | Login required | Description |
|---|---|---|
| `/` (Landing) | No | Product overview with feature highlights |
| `/demo` | No | Public demo: 84 real detections from `replay.json` played back in the browser at a fast-forward speed |
| `/login` | — | Firebase email/password authentication |
| `/app` (Dashboard) | Yes | Live counters (packets, flows, attacks, blocked IPs), protocol doughnut chart, interactive attack graph (Vis-Network), time-filtered threat log |
| `/app/users` | Admin | Lists users and changes their role (admin or viewer); accounts are added and deleted with `tools/manage_users.py` |
| `/app/audit` | Admin | Immutable audit log of blocks and unblocks |

Inside `/app` (and `/demo`) the sidebar switches between these tabs, which share the same address:

| Tab | Description |
|---|---|
| **Dashboard** | The overview described above |
| **Threats** | Threat log with search (IP or label) and filters (label, action), and a per-row **Explain** button showing severity, summary, mechanism, recommendation |
| **Topology** | Full-screen interactive network graph of attacker → target edges |
| **AI Analyst** | Chat powered by the Groq API via `/api/chat` (signed-in users only) |
| **Settings** | Engine status, model facts, confidence thresholds, known limitations |

**Time-range filter:** last hour / 24 hours (default) / 7 days / all time.

**Data source:** the dashboard reads everything from Firestore in real time. The engine also starts a local Server-Sent Events endpoint (`server.py`, `SSE_PORT` 5000), but the current dashboard does not use it.

---

### 1.9 Role-Based Access Control

| Role | Capabilities |
|---|---|
| **admin** | Everything a viewer can do, plus: manage users, view the audit log, issue unblock commands |
| **viewer** | Read the live dashboard, threat log, topology, AI analyst, settings |
| _(unauthenticated)_ | Landing page and demo only |

Rules are enforced both in `firestore.rules` (server-side) and in the React router (client-side redirect). Admins cannot remove themselves, preventing accidental lockout.

---

### 1.10 Audit Log

Every block and unblock action is written to `audit/{id}` with: UTC timestamp, actor UID, actor email, event type (`block` / `unblock` / `unblock_failed`), affected IP, and a human-readable detail string. The audit collection is append-only for browsers (`allow write: if false`).

---

### 1.11 Attack Simulation & Offline Replay

| Tool | File | Purpose |
|---|---|---|
| **One-laptop simulator** | `simulate_attack.py` | Generates port scan, SYN flood, and ICMP flood packets from reserved documentation addresses (198.51.100.x) so the engine can be demonstrated without a second machine |
| **Two-machine simulator** | `simulate_attack.py` | `--target <ip>` attacks another PC on the same network from this machine's real address; the engine on that PC detects it, and blocks the address when started with `--block` |
| **Offline replay** | `replay.py` | Runs CICIDS2017 dataset rows (or scripted attack packets when the CSVs are absent) through the real model, rules and decision logic, producing detections without live traffic, Administrator rights or the firewall; exports `public/demo/replay.json` for the browser demo |

---

### 1.12 Testing Infrastructure

The `python-engine/tests/` directory contains a full **pytest** suite:

| Test file | Covers |
|---|---|
| `test_features.py` | CICIDS2017 feature computation against known values |
| `test_classifier.py` | Model loading, prediction, evidence extraction |
| `test_rules.py` | SynFlood, PortScan, IcmpFlood thresholds and cooldowns |
| `test_detector.py` | Decision table, correlation, throttling, whitelist overrides |
| `test_blocker.py` | Whitelist logic, firewall command construction, duplicate detection |
| `test_ai.py` | Groq API calls, offline fallback, rate limiting, explanation validation |
| `test_firebase_client.py` | CloudStore writes, command handling, unblock flow (against `fake_firestore.py`) |
| `test_sinks.py` | Detection hand-off: local SSE payload, Firestore storage, explanation requests, audit of blocks |
| `test_main.py` | The `--block` / `--detect-only` start-up options |

---

### 1.13 Admin Tooling

| Script | Purpose |
|---|---|
| `tools/manage_users.py` | Add (with password-reset invite link), list, and delete users; promote/demote roles |
| `tools/seed_firestore.py` | Populate Firestore with sample threat data for dashboard development without a running engine |
| `tools/check_rules.py` | Verify that the current `firestore.rules` match the access expectations of the engine and dashboard |
| `training/verify_model.py` | Independent check that the `.pkl` produces the expected accuracy on a sample of the test set |

---

## 2. Known Limitations

| Limitation | Detail |
|---|---|
| **Botnet recall ~60%** | Botnet flows resemble ordinary web traffic at the 19-feature level. The 70% alert threshold reduces effective recall further. |
| **Web attacks not detected** | SQL injection, XSS, Infiltration, and Heartbleed were excluded from the training set due to insufficient samples. |
| **Lab-network scores** | CICIDS2017 was recorded on a controlled lab network. Live traffic on a different network produces some false positives, which the confidence threshold mitigates. |
| **Windows + IPv4 only** | The firewall integration calls `netsh` and requires Windows 10/11. IPv6 packets are not captured or classified. |
| **Blocks are permanent** | Firewall rules persist until manually removed via the dashboard, a PowerShell command, or `blocker.unblock_all()`. |
| **Single-host protection** | The engine only watches traffic on the PC it runs on; it has no visibility into other hosts on the network. |

---

## 3. Potential Future Features

### 3.1 Expanded ML Coverage

**Problem:** Web attacks (SQL injection, XSS, Heartbleed, Infiltration), encrypted-channel command-and-control, and low-and-slow attacks are not detected.

**Approach:**
- Retrain on **CIC-IDS-2018** or **UNSW-NB15**, which include HTTP-level and encryption-aware attack classes.
- Add **HTTP payload features** (URL length, number of parameters, header anomalies) extracted via deep-packet inspection (see §3.2) when traffic is unencrypted.
- Revisit **TCP initial window size**. In the training log (entry 4) it raised Botnet recall from 0.60 to 0.91 (macro F1 0.947 → 0.983, 0.986 with destination port), but it was left out on purpose: each attack class has only two or three window values, which belong to the lab's attacker machines and would not carry over to another network. It is only worth adding with training data from many different networks. (TCP flag counts were also tested and added nothing.)

**Technology:** scikit-learn (incremental retraining), XGBoost or LightGBM for faster inference, ONNX for model portability.

---

### 3.2 Deep-Packet Inspection (Layer 7)

**Problem:** The engine works at the flow-statistics level and cannot inspect payload content.

**Approach:**
- Integrate **pyshark** or **Zeek** (Bro) as a parallel capture path for protocols running on standard ports (HTTP on 80, FTP on 21, SMTP on 25).
- Extract application-layer features (HTTP method, status code, user-agent anomalies, DNS query patterns) and feed them as additional columns into a separate classifier or a rule set.
- For TLS traffic, analyse **TLS fingerprints** (JA3/JA3S hashes) to flag known malicious client or server hellos without decrypting.

**Technology:** Python `pyshark`, Zeek scripting language, `tlsfp` / `ja3` libraries.

---

### 3.3 Anomaly Detection (Unsupervised)

**Problem:** The supervised model only detects attack classes it has seen in training. Novel zero-day attacks produce no label.

**Approach:**
- Train an **Isolation Forest** or **Autoencoder** on the 19 flow features derived from benign traffic only, on the *protected host's own* traffic baseline. Any flow whose reconstruction error or anomaly score exceeds a learned threshold raises a "Suspicious / Unknown" alert.
- Gradually refine the threshold using feedback from confirmed false positives.

**Technology:** scikit-learn `IsolationForest`, PyTorch/Keras `Autoencoder`, online learning with `river` (formerly `creme`).

---

### 3.4 Real-Time Streaming Pipeline

**Problem:** As the system grows to multi-host deployment (§3.5), the current single-process queue does not scale.

**Approach:**
- Replace the in-process detection queue with **Apache Kafka** or **Redis Streams** so multiple agents on different machines can publish `PacketInfo` or flow records to a shared topic.
- A central **Apache Flink** or **Spark Structured Streaming** job consumes the topic, applies the ML model and rules, and writes results to Firestore or a time-series database.

**Technology:** Apache Kafka, Apache Flink, PySpark, `confluent-kafka-python`.

---

### 3.5 Multi-Host / Network-Wide Deployment

**Problem:** Protection is limited to the single Windows PC running the engine.

**Approach:**
- Package the Python engine as a lightweight **agent** (a Docker container or a Windows service) installable on each host to be monitored.
- Agents forward enriched flow records to a **central analysis server** over a secured gRPC channel.
- The central server aggregates events from all agents and can correlate distributed port scans or DDoS from multiple source IPs targeting multiple hosts simultaneously.
- A **network tap or span port** on a managed switch could allow a single agent to observe all LAN traffic.

**Technology:** Docker, Windows Service wrapper (`pywin32`), gRPC + `grpcio`, network taps, SPAN/mirror ports on managed switches (Cisco, Ubiquiti UniFi).

---

### 3.6 SIEM Integration & Alerting

**Problem:** Security teams already use centralised tools; CyberSentinel detections should appear there automatically.

**Approach:**
- Publish threat records to **Elastic Stack (ELK)** via the Elasticsearch Python client, enabling Kibana dashboards and alerting rules.
- Send notifications via **PagerDuty**, **Slack**, or email (SendGrid) when `CRITICAL` severity events are detected or when the blocked-IP count exceeds a threshold.
- Export detections in **STIX 2.1** format for sharing with threat-intelligence platforms.

**Technology:** `elasticsearch-py`, `slack-sdk`, `pagerduty`, `stix2` Python library, Elastic Stack 8.x.

---

### 3.7 Adaptive / Auto-Updating Model

**Problem:** Traffic patterns drift over time, causing gradual increases in false positives on production networks.

**Approach:**
- Implement **incremental learning** with `scikit-learn`'s `partial_fit` (for SGD-based classifiers) or an **online random forest** (`river` library) that updates leaf statistics as new confirmed-benign or confirmed-attack flows arrive.
- Confirmed labels can come from: admin feedback on dashboard alerts, integration with a honeypot that records only attack traffic (§3.14).
- Model versions are stored with a hash; the dashboard shows the active version and its last-updated timestamp.

**Technology:** `river` (online ML), `mlflow` for experiment tracking, Firebase Remote Config for pushing model update metadata.

---

### 3.8 IPv6 Support

**Problem:** The engine ignores IPv6 packets entirely, missing a growing fraction of real traffic.

**Approach:**
- Extend the BPF capture filter to `ip or ip6` and add an IPv6 branch to `parse_packet()` in `feature_extractor.py`.
- Retrain the model including IPv6 flow features from a dataset that covers dual-stack traffic.
- Extend the whitelist and blocker to handle IPv6 addresses and `netsh` IPv6 firewall rules.

**Technology:** Python `ipaddress` (already in use), Scapy's IPv6 layer, CIC-IDS-2018 (contains dual-stack captures).

---

### 3.9 Enhanced Dashboard & Visualisations

**Potential additions, each buildable on the existing React + Tailwind stack:**

| Feature | Technology |
|---|---|
| **Geo-IP map** of attacker locations | Leaflet.js / Mapbox GL JS + MaxMind GeoLite2 |
| **Time-series sparklines** of attack rates per class | Recharts `AreaChart` (already a dependency) |
| **Protocol heatmap** (hour × day) | D3.js or Recharts `ScatterChart` |
| **Live packet-rate gauge** | React + Recharts `RadialBarChart` |
| **Dark / light theme toggle** | Tailwind CSS `dark:` variants |
| **Exportable PDF / CSV report** | `jspdf`, `react-csv` |
| **Customisable alert thresholds** from the UI | Firestore `config` document read by the engine |
| **Push notifications** for critical alerts | Firebase Cloud Messaging (FCM) |

---

### 3.10 Automated Threat Response Playbooks

**Problem:** Blocking is all-or-nothing; different attacks warrant different responses.

**Approach:**
- Define **playbooks** in a YAML configuration file: e.g. PortScan → rate-limit only; BruteForce on SSH port → block + notify; DDoS → block + send upstream filter request.
- The detection engine matches the threat record to a playbook and executes the prescribed steps via pluggable **action adapters** (firewall, email, webhook, etc.).

**Technology:** YAML config (`pyyaml`), Python `abc`-based adapter pattern, optional integration with **n8n** or **Zapier** for no-code workflow automation.

---

### 3.11 Mobile Companion App

**Problem:** Admins cannot monitor or respond to threats on the go.

**Approach:**
- Build a **React Native** or **Flutter** app that authenticates with the same Firebase project and reads the `threats` and `stats` collections in real time.
- Push critical alerts via **Firebase Cloud Messaging** (FCM).
- Allow admins to issue unblock commands from the app by writing to the `commands` collection (the existing command-handling flow in `firebase_client.py` already handles this).

**Technology:** Flutter (Dart) or React Native, Firebase FCM, `firebase_messaging` Flutter plugin.

---

### 3.12 LLM-Powered Security Analyst Chat

The AI Analyst tab already exists. Each question is sent with a summary of the detections on screen (counts by label and action, top 5 source IPs, the 10 latest detections). Enhancements:

- **Retrieval-Augmented Generation (RAG):** look up the full history of the IPs and attacks a question mentions, beyond the on-screen summary, so the model can answer questions like "Why was this IP blocked three times this month?"
- **Threat summarisation:** a scheduled Cloud Function generates a daily digest ("You had 47 attacks today; 30 were port scans from 12 distinct IPs…") delivered by email or push notification.
- **Fine-tuned model:** fine-tune a small open-source LLM (Llama 3, Mistral) on CyberSentinel alert data for lower latency and offline operation.

**Technology:** Groq API (already integrated), LangChain / LlamaIndex for RAG, Firebase Cloud Functions for scheduled digests, Ollama for local LLM inference.

---

### 3.13 Cross-Platform Engine

**Problem:** The engine requires Windows because of `netsh` and Npcap.

**Approach:**
- Abstract the blocker into a platform adapter interface with implementations for:
  - **Linux:** `iptables` / `nftables` via subprocess, or `python-iptables`
  - **macOS:** `pf` (Packet Filter) via subprocess
- Scapy already works on Linux and macOS; the packet-capture layer needs minimal changes.
- The flow tracker and ML classification layers are already platform-independent Python.

**Technology:** Python `abc` adapter, `python-iptables`, Docker (for isolated testing on Linux).

---

### 3.14 Threat Intelligence Feeds

**Problem:** Known-bad IP addresses from public blocklists are not checked before or after a detection.

**Approach:**
- On engine startup and on a periodic timer, download and parse feeds such as **AbuseIPDB**, **Emerging Threats**, or **Spamhaus DROP** into an in-memory set.
- Any flow from a listed IP immediately triggers a "Threat Intel" alert and optional block, independently of the model and rules.
- Integrate **VirusTotal** or **Shodan** lookups as an optional enrichment step appended to the Firestore threat document.

**Technology:** `requests` (already a dependency), `maxminddb` for GeoLite2, AbuseIPDB API, `shodan` Python client.

---

### 3.15 Federated / Privacy-Preserving Learning

**Problem:** Sharing raw network traffic or flow records for retraining raises privacy concerns for enterprise users.

**Approach:**
- Use **Federated Learning** (FL): each agent trains a local model update on its own traffic; only the gradient updates (not the raw data) are sent to a central aggregator using the **Flower** (flwr) framework.
- **Differential privacy** noise (via `tensorflow-privacy` or `opacus`) is added to gradient updates before transmission so individual flow statistics cannot be recovered.

**Technology:** `flwr` (Flower FL framework), `opacus` (PyTorch differential privacy), gRPC transport.

---

*Document generated from a full scan of the repository on 2026-10-28.*

