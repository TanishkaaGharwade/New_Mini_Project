# CyberSentinel: Poster Presentation Guide

Everything you need to present the poster with confidence: what each line means, where each
number comes from, how it was tested, and how to prove it live in front of the examiner.

Read it in order. Parts 1–3 are the basics; you need them to understand everything after.

**Contents**

1. [The project in one minute](#1-the-project-in-one-minute)
2. [Words you must know](#2-words-you-must-know)
3. [The dataset: CICIDS2017](#3-the-dataset-cicids2017)
4. [The 19 features](#4-the-19-features)
5. [How the code is organised](#5-how-the-code-is-organised)
6. [The model](#6-the-model)
7. [The poster, line by line](#7-the-poster-line-by-line)
8. [Every number on the poster: source and proof](#8-every-number-on-the-poster-source-and-proof)
9. [The results, word by word](#9-the-results-word-by-word)
10. [The confusion matrix in detail](#10-the-confusion-matrix-in-detail)
11. ["0 to 600 of 600 probes" explained](#11-0-to-600-of-600-probes-explained)
12. [How the project was tested](#12-how-the-project-was-tested)
13. [Live demo in front of the examiner](#13-live-demo-in-front-of-the-examiner)
14. [What we must not claim](#14-what-we-must-not-claim)
15. [Likely examiner questions](#15-likely-examiner-questions)
16. [Where everything is](#16-where-everything-is)

---

## 1. The project in one minute

Think of the laptop as a **house**:

| Real thing | House picture |
|---|---|
| **Packet** | A letter. Everything on a network travels as small letters. One web page = hundreds of letters. |
| **IP address** | The house address written on the letter, e.g. `192.168.1.2`. |
| **Port** | A door number. Websites use door 443, logins use other doors. |
| **Flow** | One conversation: all letters between the same two houses through the same doors, from "hello" to "bye". |
| **Attack** | Someone sending harmful letters: too many of them, or knocking on every door to find a weak one. |
| **Firewall** | The security guard at the gate. Told to "block this address", it throws away every letter from it. |
| **Machine-learning model** | A program that learned from examples. We showed it millions of conversations labelled "normal" or "attack type X", and it learned the patterns. |

**What CyberSentinel does:** it reads every letter → groups them into conversations → decides
whether each conversation is an attack → tells the guard to block attackers → explains each
attack in plain English → shows everything on a website.

---

## 2. Words you must know

| Word | Simple meaning |
|---|---|
| **IDS / IPS** | Intrusion Detection System (notices attacks) / Intrusion Prevention System (also stops them). We are both. |
| **Benign** | Normal, harmless traffic. |
| **Dataset** | A big table of examples the model learns from. Each row = one conversation, with a label saying what it was. |
| **Label / class** | The correct answer for a row: Benign, DoS, DDoS, PortScan, BruteForce or Botnet. |
| **Feature** | One number describing a conversation, e.g. "how long it lasted". We use 19. |
| **Training** | The model studying the labelled rows. |
| **Test set** | Rows hidden from the model during training, used as its final exam. |
| **Random Forest** | Our model: 100 decision trees that vote. |
| **Confidence** | The share of the 100 trees that voted for the winning answer. 90 trees saying "DoS" = 90%. |
| **Rate rule** | A simple counting rule, e.g. "more than 100 connection requests in 2 seconds from one address". |
| **Whitelist** | Addresses we never block: this laptop, the router (gateway), the DNS server. |
| **netsh** | The Windows command that adds and removes firewall rules. |
| **Firestore** | Google's free online database. The engine saves detections there; the website reads them. |
| **LLM / Groq** | LLM = an AI that writes text (like ChatGPT). Groq = the company whose servers run that AI for us. |
| **React dashboard** | Our website, built with React (a tool for making websites). |
| **Scapy / Npcap** | Npcap = a Windows driver that lets programs see network traffic. Scapy = the Python library that reads the packets. |
| **TCP / UDP / ICMP** | TCP = proper conversations (web pages, logins). UDP = quick one-off messages (DNS lookups). ICMP = "ping" (are you there?). |
| **SYN** | The "can we talk?" packet that starts every TCP connection. |
| **Unit test** | A small automatic check of one piece of code ("given this input, is the output right?"). |

**The attacks:**

| Attack | Simple meaning |
|---|---|
| **DoS** (Denial of Service) | One attacker sends so many requests that the service is too busy for real users. Like 1,000 fake customers blocking a shop door. |
| **DDoS** (Distributed DoS) | The same, from many computers at once. |
| **PortScan** | Knocking on every door to see which are open. Usually the first step before a real attack. |
| **BruteForce** | Guessing a password again and again (here: FTP and SSH logins). |
| **Botnet** | An infected computer secretly taking orders from the attacker's server. |
| **SYN flood** | Thousands of "can we talk?" packets that never finish the conversation. |
| **ICMP flood** | Thousands of pings. |

---

## 3. The dataset: CICIDS2017

### What it is

**CICIDS2017** was made by the Canadian Institute for Cybersecurity (University of New
Brunswick) in 2017 — reference **[1]** on the poster. They built a small company network in a
lab, ran normal office activity for 5 days (Monday to Friday), launched real attacks on it, and
recorded all the traffic. Their tool (CICFlowMeter) turned the recording into a table: one row
per conversation, 78 numbers per row, plus a label saying what that conversation really was.

We use the "MachineLearningCSV" version: 8 CSV files, one or two per day.

### The 8 files (counted by us, training log entry 2)

| File (day) | Rows | What is in it |
|---|---|---|
| Monday | 529,918 | Only normal traffic |
| Tuesday | 445,909 | Normal + FTP and SSH password guessing |
| Wednesday | 692,703 | Normal + 4 kinds of DoS + Heartbleed |
| Thursday morning | 170,366 | Normal + web attacks (password guessing on a website, XSS, SQL injection) |
| Thursday afternoon | 288,602 | Normal + Infiltration |
| Friday morning | 191,033 | Normal + Botnet |
| Friday afternoon (PortScan) | 286,467 | Normal + port scans |
| Friday afternoon (DDoS) | 225,745 | Normal + DDoS |
| **Total** | **2,830,743** | 15 different labels |

80% of all rows are normal (BENIGN). Some attacks are very rare: Heartbleed has only 11 rows,
SQL injection 21.

### How we cleaned it (step by step)

Cleaning = removing rows that are broken or would make the test unfair. Done in the training
notebook; each step's row count is printed there.

| Step | What we did and why | Rows left |
|---|---|---|
| 0. Load | All 8 files together | 2,830,743 |
| 1. Group labels | The 15 original labels → our 6 classes (table below). Attack types with too few rows to learn from (Web attacks, Infiltration, Heartbleed — 2,227 rows) were **dropped**. | 2,828,516 |
| 2. Remove broken rows | Some rows have "Infinity" or empty values (a speed divided by a zero duration) or a negative duration. A model can't learn from impossible numbers. | 2,825,534 |
| 3. Remove exact duplicates | Many rows were exact copies (42.9% of PortScan rows!). If a copy lands in the training part and another copy in the test part, the model has "seen the exam question" — the score would be falsely high. | **2,476,428** |
| 4. Reduce normal rows | 2,053,034 normal rows would drown out the attacks, so we randomly kept **500,000** of them (all attack rows kept). | 923,394 |
| 5. Split 80 / 20 | 80% to study, 20% hidden for the exam (details below). | 738,715 train / 184,679 test |

**How the 15 labels became 6 classes:**

| Original labels | Our class |
|---|---|
| BENIGN | Benign |
| DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest | DoS |
| DDoS | DDoS |
| PortScan | PortScan |
| FTP-Patator, SSH-Patator | BruteForce |
| Bot | Botnet |
| Web Attack (3 kinds), Infiltration, Heartbleed | dropped (too few examples) |

### The 80/20 stratified split

- **80/20:** 80% of the rows (738,715) are given to the model to learn from. The other 20%
  (184,679) are locked away and only used at the end, as the exam.
- **Stratified:** each class appears in the same proportion in both parts, so the exam has
  every attack type in fair amounts.
- **Seed 42:** the random shuffle uses a fixed starting number, so running it again gives the
  exact same split — anyone can reproduce our numbers.

| Class | Train | Test |
|---|---|---|
| Benign | 400,000 | 100,000 |
| Botnet | 1,559 | 389 |
| BruteForce | 7,318 | 1,830 |
| DDoS | 102,409 | 25,602 |
| DoS | 154,874 | 38,719 |
| PortScan | 72,555 | 18,139 |
| **Total** | **738,715** | **184,679** |

### The "unseen benign" set (1.55 million flows)

In step 4 we used 500,000 of the 2,053,034 normal rows. The other **1,553,034 normal rows were
never used** — not for training, not for testing. We used them later as an extra test: "how
often does the model wrongly shout *attack* at normal traffic?"

### Where the data lives

`training/data/MachineLearningCVE/` — **only on Tanishka's laptop** (the files are 800+ MB, so
they are not on GitHub). Download: `MachineLearningCSV.zip` from
https://www.unb.ca/cic/datasets/ids-2017.html. This is why the live proofs must run on that laptop.

---

## 4. The 19 features

For each conversation the engine calculates these 19 numbers — the same ones CICIDS2017 uses,
calculated the same way. *Forward* = from the side that started the conversation; *backward* =
the replies.

| # | Feature | Simple meaning |
|---|---|---|
| 1 | Flow Duration | How long the conversation lasted (microseconds) |
| 2 | Total Fwd Packets | Letters sent by the starter |
| 3 | Total Backward Packets | Letters sent back |
| 4 | Total Length of Fwd Packets | Total bytes of data the starter sent |
| 5 | Total Length of Bwd Packets | Total bytes sent back |
| 6 | Fwd Packet Length Max | Biggest letter from the starter |
| 7 | Fwd Packet Length Mean | Average letter size from the starter |
| 8 | Bwd Packet Length Max | Biggest reply |
| 9 | Bwd Packet Length Mean | Average reply size |
| 10 | Packet Length Mean | Average size of all letters |
| 11 | Packet Length Std | How much letter sizes vary |
| 12 | Flow Bytes/s | Bytes per second |
| 13 | Flow Packets/s | Letters per second |
| 14 | Flow IAT Mean | Average gap between two letters ("IAT" = inter-arrival time) |
| 15 | Flow IAT Std | How much the gaps vary |
| 16 | Flow IAT Max | Longest gap |
| 17 | Fwd IAT Mean | Average gap between the starter's letters |
| 18 | Bwd IAT Mean | Average gap between replies |
| 19 | Down/Up Ratio | Replies ÷ starter letters |

**Why these 19 and not all 78?** We tested extra groups (training log entry 4):
- **TCP flag counts** (SYN, FIN…): broken in the dataset (never above 1) and added nothing.
- **Window size and destination port:** raised the score (macro F1 0.947 → 0.986), but only
  because each attack in the lab came from a few specific machines with specific settings. The
  model would be recognising *the lab's computers*, not attacks — useless on another network.
  So we kept the 19 that describe *behaviour*.

The most useful features for the model were letter-size features (Packet Length Std, Bwd
Packet Length Mean, Total Length of Fwd Packets).

---

## 5. How the code is organised

```
New_Mini_Project/
├── python-engine/          The engine (runs on the protected Windows PC)
│   ├── main.py             Starts everything; --block or --detect-only
│   ├── sniffer.py          Reads packets (Scapy + Npcap)
│   ├── feature_extractor.py  Packets → conversations → the 19 numbers
│   ├── rules.py            The 3 counting rules (SYN flood, port scan, ICMP flood)
│   ├── classifier.py       Loads the model, gets its answer + confidence
│   ├── detector.py         The decision table: block / alert / ignore
│   ├── blocker.py          Whitelist + Windows Firewall rules (netsh)
│   ├── sinks.py            Hands each detection to console, cloud and AI
│   ├── firebase_client.py  Saves to Firestore; handles "unblock" requests
│   ├── ai.py               Groq explanations (offline text if Groq is down)
│   ├── netinfo.py          Finds this PC's addresses, gateway and DNS (for the whitelist)
│   ├── server.py           Small local live feed (not used by the current website)
│   ├── config.py           Every setting (thresholds, time windows) in one place
│   ├── simulate_attack.py  Fake attacker for demos
│   ├── replay.py           Builds the demo data from the real model
│   ├── models/model_v1.pkl The trained model (7.8 MB)
│   ├── tests/              The 182 automatic tests
│   └── tools/              Admin scripts: manage_users.py, check_port_scan.py, ...
├── training/               How the model was made
│   ├── train_cicids2017.ipynb  The training notebook (with saved results)
│   ├── TRAINING_LOG.md     Diary of every experiment and result (entries 1–15)
│   ├── reports/            model_v1.md report + confusion matrix picture
│   ├── features.json       The list of the 19 features
│   ├── verify_model.py     Proof script: false alarms on unseen normal traffic
│   └── check_test_set.py   Proof script: re-scores the test set (99.56%)
├── frontend/               The website (React)
│   ├── src/pages/          Landing, Demo/Dashboard, Login, Users, Audit log
│   ├── api/chat.js         The AI Analyst chat (talks to Groq)
│   └── public/demo/replay.json  84 recorded detections for the demo
├── firestore.rules         Who may read/write what in the database
└── docs/                   Documentation (this file)
```

**How one packet travels through the files:**

`sniffer.py` reads it → `feature_extractor.py` adds it to its conversation → `rules.py` counts
it → when the conversation ends, `feature_extractor.py` computes the 19 numbers →
`classifier.py` asks the model → `detector.py` decides → `blocker.py` blocks (if needed) →
`sinks.py` sends the record to `firebase_client.py` (Firestore) and `ai.py` (explanation) →
the website shows it.

**When does a conversation end?** When it is closed normally (FIN) or refused (RST), after 15
seconds of silence, after 120 seconds in total, or when 50,000 conversations are open at once
(the oldest is closed).

---

## 6. The model

- **Type:** Random Forest **[2]**, built with the scikit-learn library **[3]**.
- **What a Random Forest is:** 100 *decision trees*. A decision tree is a chain of yes/no
  questions, e.g. "Did it last under 1 ms? → yes. Was the reply exactly 6 bytes? → yes. → PortScan."
  Each tree learns from a slightly different random part of the data, so they make different
  mistakes. All 100 vote; the majority wins. Many voters make fewer mistakes than one.
- **Settings:** 100 trees, each at most 20 questions deep, at least 2 examples per final answer,
  random seed 42. Empty values are filled with the column's middle value (median imputer).
- **Training time:** 33 seconds. **File size:** 7.8 MB.
- **Why Random Forest?** Research shows it scores among the best on this kind of data; it needs no
  scaling of numbers; it gives a confidence for every answer (we need that for the 70% and 90%
  rules); it is fast enough to judge every conversation live.
- **Why no "class weighting"** (making rare classes count more)? We tried it (training log
  entry 5): Botnet recall rose to 0.97 but Botnet precision fell to 0.12 — 7 out of 8 "Botnet"
  alarms would have been wrong. Not worth it.

---

## 7. The poster, line by line

### Header and title

- **"Sardar Patel Institute of Technology / Department of Computer Engineering / Academic Year 2026-27"** — college, department, year.
- **"CyberSentinel: Real-Time Network Threat Mitigation Engine using Predictive Analytics"**
  - *Real-time* — works while traffic is happening.
  - *Threat mitigation* — reduces or stops attacks.
  - *Predictive analytics* — a model predicts "attack or not".

### Abstract

| Line | Meaning |
|---|---|
| "a real-time network intrusion detection and prevention system for Windows" | Notices attacks on a Windows PC as they happen, and stops them. |
| "A Python engine captures packets, builds flows" | Our Python program reads every letter and groups them into conversations. |
| "and computes 19 CICIDS2017 features for a Random Forest classifier" | For each conversation it calculates the 19 numbers of Part 4 and gives them to the model, which sorts it into Benign or an attack type. |
| "supported by rate rules for floods and scans" | Plus three simple counting rules. |
| "Confirmed attackers are blocked through Windows Firewall" | The engine adds a firewall rule that drops the attacker's traffic. |
| "every detection is stored in Firestore" | Saved in the online database. |
| "explained in plain English by a Groq-hosted LLM" | An AI writes what happened and what to do. |
| "shown on a React dashboard" | Our website shows it live. |
| "99.56% accuracy on 184,679 test flows [4]" | On 184,679 conversations it never saw, 99.56% were labelled correctly. [4] = our own experiment report. |
| "Testing: 182 unit tests, a held-out test set, 1.55 million unseen benign flows, synthetic attacks and a live run" | The five ways we checked it (Part 12). |

### Introduction

- **"Modern networks carry huge traffic volumes, so threats hidden in legitimate traffic are easy to miss."** — Thousands of letters a minute; no human can read them all.
- **"Signature tools miss new attack variants"** — Older tools (Snort, Suricata) compare traffic with a list of known attack patterns ("signatures"). A slightly changed attack doesn't match the list. A learned model judges *behaviour*, so it can still notice it.
- **"commercial IPS products are costly and closed"** — Cisco or Palo Alto products are expensive and you can't see how they work. Ours is free and open.

### Objectives

1. **Capture and monitor live network traffic** — read every letter as it arrives.
2. **Classify flows with a CICIDS2017 Random Forest** — decide for each conversation: normal, or which attack.
3. **Auto-block attackers through Windows Firewall** — block without a person having to act.
4. **Show and explain detections on a live dashboard** — website with plain explanations.

### Problem Definition

- **"Detect DoS, DDoS, port scans, brute force, botnets and floods in a Windows PC's live traffic"** — the attack types in Part 2.
- **"block attackers without blocking trusted hosts"** — the whitelist: never block this laptop, the router (gateway) or DNS. Blocking them would cut off our own internet.
- **"explain each decision in plain language"** — every alert comes with an explanation.

### Contribution

- **"An open pipeline from capture to an explained, role-protected dashboard."** — One complete chain from reading packets to the website. *Role-protected*: you must log in; an **admin** can unblock addresses and manage users, a **viewer** can only look.
- **"Matching CICIDS2017's feature conventions raised port-scan detection from 0 to 600 of 600 probes without retraining."** — Our key discovery. Full story in Part 11.
- **"The model alone blocks only after 3 confident flows in 10 s."** — Safety rule: if *only the model* (no counting rule) says "attack", it must happen 3 times from the same address within 10 seconds before we block. One accidental connection is reported, not blocked.

### Design

- **"Layered, event-driven engine"** — the work is split into stages (read → group → decide), and each stage starts when new data arrives.
- **"with threads joined by bounded queues"** — each stage is a separate worker (*thread*) running at the same time, like people on an assembly line. Between workers is a waiting line (*queue*) with a maximum length (*bounded*). If one worker is slow, the line fills and extra items are dropped and counted — the program never freezes.
- **"engine and dashboard communicate only through Firestore"** — the website never connects to the laptop. The engine writes to the online database; the website reads it. The laptop opens no door to the internet, which is safer.

### The design diagram

```
[Live capture] → [Flow tracker] → [Random Forest + rate rules] → [Decision table]
                                                                   │         │
                                                                record     block
                                                                   ↓         ↓
[React dashboard] ← live updates ← [Cloud Firestore] ⇄ [Groq LLM]  [Windows Firewall]
```

| Box / arrow | Meaning |
|---|---|
| **Live capture (Scapy + Npcap)** | Reads every letter in and out of the laptop. |
| **Flow tracker, 19 CICIDS2017 features** | Groups letters into conversations; computes the 19 numbers when a conversation ends. |
| **Random Forest + rate rules** | Two judges: the model judges each finished conversation; the rules count letters per sender in real time. |
| **Decision table (block / alert / ignore)** | Combines both judges into one action (table below). |
| **"block" → Windows Firewall (netsh)** | Adds a firewall rule named `CyberSentinel Block <address>`. |
| **"record" → Cloud Firestore** | Saves every detection: time, attacker address, attack type, confidence, action. |
| **Firestore ⇄ Groq LLM** | The record's details go to the AI; its explanation is saved back into the same record. (Exact detail: the engine sends the details to Groq and writes the answer into Firestore — the diagram draws it simply.) |
| **"live updates" → React dashboard (login, roles)** | The website shows each new record within seconds, after login. |

**The decision table:**

| Counting rule fired? | Model says attack? | Confidence | Action |
|---|---|---|---|
| yes | yes | 70% or more | **block** (trigger "both") |
| yes | no | – | **block** (trigger "rule") |
| no | yes | 90% or more, 3 times in 10 s | **block** (trigger "model") |
| no | yes | 70–90% | **alert only** |
| no | no, or under 70% | – | ignore (no record) |

Then two safety checks: whitelisted address → never blocked; engine in detect-only mode →
recorded but the firewall is not touched.

**Follow one attack through the diagram:** someone knocks on 60 doors in 2 seconds → capture reads
all 60 → the port-scan rule sees more than 20 doors in 5 seconds and fires → decision: block →
netsh blocks the address → the record is saved in Firestore → Groq adds "This was a port scan…"
→ a red node appears on the website.

### Methodology / Algorithms

| Line | Meaning |
|---|---|
| "Trained on CICIDS2017 [1] (2.83 million flows, cleaned and de-duplicated; 80/20 stratified split)" | Part 3: 2,830,743 conversations; broken rows and exact copies removed; 80% to learn, 20% for the exam, each class in the same proportion. |
| "1. Capture IPv4 TCP/UDP/ICMP packets (Scapy, Npcap)" | Read all common internet traffic (IPv4 addresses like 192.168.1.2). |
| "2. Build flows and compute 19 CICIDS2017 features" | Group into conversations; compute the 19 numbers. |
| "3. A Random Forest [2] (100 trees, scikit-learn [3]) labels Benign, DoS, DDoS, PortScan, BruteForce or Botnet" | 100 trees vote on one of 6 answers. |
| "verdicts under 70% confidence are ignored" | If fewer than 70 of 100 trees agree, we treat it as normal. Reason: in our live test, normal web downloads were sometimes called "DoS" at 36–69% confidence. This rule cut false alarms by a third. |
| "4. Rate rules: over 100 SYN or ICMP packets in 2 s, or over 20 ports in 5 s, from one source" | SYN flood, ICMP flood and port scan rules. They react instantly and catch floods the model never learned. |
| "5. Block via netsh on a rule hit, or after 3 verdicts of at least 90% in 10 s; own IPs, gateway and DNS are never blocked" | The decision table above. |
| "6. Store in Firestore; Groq explains each detection" | Save online; AI explanation (severity, what happened, how it works, what to do). If Groq is unavailable, a pre-written explanation is used. |
| "Assumption: live traffic resembles the CICIDS2017 lab network" | The model learned from one lab in 2017; we assume real traffic is similar enough. If not, accuracy drops — which is why the rules and thresholds back it up. |

### Results

Each number is explained in Part 9, and its proof is in Part 8.

| Line | Short meaning |
|---|---|
| "Test set (184,679 flows) [4]: accuracy 99.56%" | 183,875 of the 184,679 exam conversations were labelled correctly. |
| "macro F1 0.947" | Average of the six per-class scores — fair to small classes. |
| "recall DDoS 0.999, PortScan 0.999, DoS 0.992, BruteForce 0.972, Botnet 0.596" | Share of each real attack type that was caught. |
| "False alarms on 1.55 million unseen benign flows: 0.247% (0.161% with the 70% threshold)" | 3,833 of 1,553,034 normal conversations were wrongly called attacks (2,498 with the 70% rule). |
| "182/182 tests pass" | All 182 automatic code checks succeed. |
| "Live test on one laptop: simulated scans and floods were detected, and the scanner was blocked by a real Windows Firewall rule" | Real engine on a real laptop; a fake attacker program on the same laptop; real firewall rule created. |
| "Left: confusion matrix; right: dashboard (demo replay)" | Part 10, and the screenshot explained below. |

**The dashboard screenshot (right picture):** the website in **demo mode**, which replays 84
detections recorded from the real model (so it works without the engine).
- **Top counters:** total packets, attacks detected, IPs blocked, total flows (they grow as the replay runs; the screenshot is one moment).
- **Protocol chart:** how many attacks used TCP vs ICMP.
- **Network graph:** the centre box is the protected laptop; each diamond is an attacker — **red = blocked**, **orange = alert only**.
- **Threat log:** one row per detection: time, attacker address, attack type, confidence, trigger (rule or model), action (Blocked / Alert only), and an **Explain** button that opens the AI's explanation.
- The orange banner says "Simulated replay of recorded attack traffic. Not live data." — we never pretend the demo is live.

### Conclusion

- **"combines a CICIDS2017 Random Forest with rate rules to detect, block and explain attacks on a Windows PC in real time"** — model + counting rules find attacks, the firewall blocks, the AI explains, live.
- **"Limitations: low Botnet recall"** — only about 60% of botnet traffic is caught.
- **"no web-attack detection"** — SQL injection and XSS hide inside website forms; the dataset had too few examples (Part 3, step 1).
- **"Windows/IPv4 only"** — blocking uses Windows commands; the newer IPv6 address format is not read.
- **"Future work: attacks from a second machine and newer datasets"** — real attacks from another computer; training on newer data such as CIC-IDS2018.

### References

| Ref | What it is | Why we cite it |
|---|---|---|
| [1] Sharafaldin et al., ICISSP 2018 | The paper by the creators of CICIDS2017 | Our training data |
| [2] Breiman, Machine Learning 2001 | The paper that invented Random Forests | Our model type |
| [3] Pedregosa et al., JMLR 2011 | The paper describing scikit-learn | The library we built the model with |
| [4] Own experiments | Our model report and training log | Where every poster number was recorded |

---

## 8. Every number on the poster: source and proof

**All the model numbers are our own measurements**, not copied from a paper. The training
notebook printed them, and they were saved in `training/reports/model_v1.md` and
`training/TRAINING_LOG.md`. The proof scripts below re-calculate them from scratch in under a
minute — the saved model is loaded and re-scored, **not** retrained.

| Poster number | Where it was recorded | Proof command (run in the project folder) | Time |
|---|---|---|---|
| 2.83 million flows | Notebook output; log entry 2 | `python training/check_test_set.py` (first line) | 33 s |
| 80/20 split, 184,679 test flows | Notebook split table; log entry 6 | same script (first line) | – |
| 100 trees | Notebook; model report | – (open `training/reports/model_v1.md`) | – |
| Accuracy 99.56%, macro F1 0.947, all recalls | Notebook classification report; log entry 6 | `python training/check_test_set.py` | 33 s |
| 0.247% false alarms on 1.55 million flows | Log entry 8 | `python training/verify_model.py` | 52 s |
| 0.161% with the 70% threshold | Log entry 14 | `python training/verify_model.py` (line "auto-blocked at confidence >= 0.70") | – |
| 182/182 tests pass | – | `cd python-engine` then `python -m pytest -q` | 14 s |
| 0 to 600 of 600 probes | Log entries 11, 12, 15 | `python python-engine/tools/check_port_scan.py` | 14 s |
| 70%, 100 SYN in 2 s, 20 ports in 5 s, 90%, 3 flows in 10 s | `python-engine/config.py` lines 16–69 | Open the file; the tests in `test_detector.py` and `test_rules.py` check these limits | – |
| Live test on one laptop | Log entry 13 | The live demo, Part 13 | 5 min |
| Confusion matrix | `training/reports/model_v1_confusion_matrix.png` | Counts printed by the notebook (log entry 6) | – |

**Expected output of `check_test_set.py`** (matches the poster exactly):

```
2,830,743 raw flows -> 2,476,428 after cleaning -> 738,715 train, 184,679 test
Scoring model_v1.pkl (not retrained)

              precision    recall  f1-score   support
      Benign     0.9945    0.9976    0.9961    100000
      Botnet     0.8788    0.5964    0.7106       389
  BruteForce     0.9989    0.9721    0.9853      1830
        DDoS     0.9994    0.9988    0.9991     25602
         DoS     0.9962    0.9920    0.9941     38719
    PortScan     0.9966    0.9989    0.9978     18139
    accuracy                         0.9956    184679
   macro avg     0.9774    0.9260    0.9472    184679
```

**Expected output of `verify_model.py`** (part):

```
[2] unseen benign flows: 1,553,034
    flagged as any attack: 3,833 (0.247%)
    would be auto-blocked at confidence >= 0.70: 2,498 (0.161%)
```

**Expected output of `check_port_scan.py`** (end):

```
Scan probes labelled PortScan before the fix: 0 of 600
Scan probes labelled PortScan after  the fix: 600 of 600
Normal flows labelled as an attack after the fix: 0
RESULT: matches TRAINING_LOG.md entry 12
```

> **Do not re-run the training notebook in front of the examiner.** It refuses to overwrite the
> existing model file (by design), and it takes about 5 minutes. To show the notebook, just open
> it — the saved outputs are visible without running it. Use `check_test_set.py` for a live proof.

---

## 9. The results, word by word

All numbers below are from the 184,679-flow test set unless stated otherwise.

### Accuracy = 99.56%

**Correct answers ÷ all answers.** 183,875 correct ÷ 184,679 = 0.9956 = 99.56%. Only 804
conversations were labelled wrongly.

*Why accuracy alone is not enough:* 100,000 of the 184,679 exam rows are normal. A model that
only knew "normal" would already score 54%. So we also report per-class scores.

### Precision

**Of all the times the model said "X", how often was it right?** It measures *false alarms*.
Botnet precision 0.879: the model said "Botnet" 264 times; 232 were real Botnet, 32 were normal
traffic. 232 ÷ 264 = 0.879.

### Recall

**Of all the real X in the exam, how many did the model catch?** It measures *missed attacks*.

| Class | Caught ÷ real | Recall |
|---|---|---|
| DDoS | 25,572 ÷ 25,602 | 0.999 |
| PortScan | 18,119 ÷ 18,139 | 0.999 |
| DoS | 38,411 ÷ 38,719 | 0.992 |
| BruteForce | 1,779 ÷ 1,830 | 0.972 |
| Botnet | 232 ÷ 389 | **0.596** |

**Why is Botnet low?** A botnet computer quietly checks in with its control server using ordinary
web-like requests, so its conversations look like normal browsing in these 19 numbers. And there
were only about 1,900 Botnet examples in the whole dataset — too few to learn the small
differences. All 157 missed Botnet conversations were called "Benign".

### F1 score

**One score that combines precision and recall** (their "harmonic mean"). It is only high if the
model both catches the attacks *and* avoids false alarms. For Botnet:
2 × 0.879 × 0.596 ÷ (0.879 + 0.596) = **0.711**.

### Macro F1 = 0.947

**The plain average of the six F1 scores**, so every class counts equally — the small Botnet
class counts as much as the huge Benign class:

(0.996 Benign + 0.711 Botnet + 0.985 BruteForce + 0.999 DDoS + 0.994 DoS + 0.998 PortScan) ÷ 6 = **0.947**

This is the fairest single number, because Botnet's weakness pulls it down instead of hiding.

### False alarms: 0.247% → 0.161%

On the **1,553,034 normal conversations the model never saw** (Part 3):
- It wrongly called **3,833** of them an attack = **0.247%** (about 2–3 per 1,000).
- Counting only answers with at least 70% confidence (what the engine really uses): **2,498** = **0.161%** (about 1–2 per 1,000). That is 35% fewer.
- This agrees with the test set (0.238%), which shows the test-set result was not luck.

### The 70% threshold's cost

Ignoring weak answers also hides some real attacks. On the test set (log entry 14):
attacks reported 99.35% → 99.14%; Botnet 59.6% → 50.4%; the other classes lose less than half a
point. We accepted that cost to cut false alarms on real traffic.

### "182/182 tests pass"

182 automatic checks of the engine's code; all pass in about 14 seconds. Part 12 lists them.

---

## 10. The confusion matrix in detail

The confusion matrix answers: **"when the real answer was X, what did the model say?"**

**How to read it:**
- **Rows** = the true class (what the conversation really was).
- **Columns** = the class the model predicted.
- **The diagonal** (top-left to bottom-right) = correct answers.
- **Everything off the diagonal** = mistakes.

### With counts (from the notebook, log entry 6)

| True ↓ / Predicted → | Benign | Botnet | BruteForce | DDoS | DoS | PortScan | Total |
|---|---|---|---|---|---|---|---|
| **Benign** | **99,762** | 32 | 2 | 14 | 131 | 59 | 100,000 |
| **Botnet** | 157 | **232** | 0 | 0 | 0 | 0 | 389 |
| **BruteForce** | 51 | 0 | **1,779** | 0 | 0 | 0 | 1,830 |
| **DDoS** | 29 | 0 | 0 | **25,572** | 1 | 0 | 25,602 |
| **DoS** | 304 | 0 | 0 | 2 | **38,411** | 2 | 38,719 |
| **PortScan** | 7 | 0 | 0 | 0 | 13 | **18,119** | 18,139 |

Diagonal total: 99,762 + 232 + 1,779 + 25,572 + 38,411 + 18,119 = **183,875 correct** → 99.56%.

### The poster's version (each row divided by its total)

The picture on the poster shows the same table as **fractions of each row**, so every row adds up
to 1. That makes small and big classes easy to compare.

| True ↓ / Predicted → | Benign | Botnet | BruteForce | DDoS | DoS | PortScan |
|---|---|---|---|---|---|---|
| **Benign** | **0.998** | 0.000 | 0.000 | 0.000 | 0.001 | 0.001 |
| **Botnet** | 0.404 | **0.596** | 0.000 | 0.000 | 0.000 | 0.000 |
| **BruteForce** | 0.028 | 0.000 | **0.972** | 0.000 | 0.000 | 0.000 |
| **DDoS** | 0.001 | 0.000 | 0.000 | **0.999** | 0.000 | 0.000 |
| **DoS** | 0.008 | 0.000 | 0.000 | 0.000 | **0.992** | 0.000 |
| **PortScan** | 0.000 | 0.000 | 0.000 | 0.000 | 0.001 | **0.999** |

(0.000 does not always mean zero — e.g. 32 of 100,000 = 0.0003, which rounds to 0.000.)

**The diagonal numbers are exactly the recall values on the poster.** Darker squares = bigger numbers.

### What it tells us

1. **Very strong on four attack types:** DDoS, PortScan, DoS and BruteForce are caught 97–99.9% of the time.
2. **The one weakness is Botnet:** row 2 — 0.596 caught, **0.404 (157 conversations) called Benign**. That light-blue square is the main thing to point at.
3. **Almost all mistakes go to "Benign"** (the first column): when the model is wrong about an attack, it misses it rather than confusing one attack with another. Attack-vs-attack confusion is tiny (13 PortScan called DoS, 2 DoS called DDoS…).
4. **Few false alarms:** row 1 — of 100,000 normal conversations, 238 were called an attack (32 + 2 + 14 + 131 + 59). Most of those (131) were called DoS.

---

## 11. "0 to 600 of 600 probes" explained

### What a "probe" is

In a port scan, the attacker sends one "can we talk?" packet (SYN) to a door (port). The door
answers "no, closed" (a reset, RST) or "yes". **One knock + its answer = one probe** = one tiny
conversation. A scan of 300 doors = 300 probes.

### What happened (training log entries 11 and 12, 13 October)

1. We built two realistic port scans of **300 doors each** (two common styles of the scanning
   tool nmap) = **600 probes**, and ran them through our engine's own code.
2. The model called **all 600 "Benign" — 0 of 600 detected.** The model scored 99.9% on PortScan
   in the dataset, so something was wrong.
3. We investigated the dataset's PortScan rows. 99% of them had a reply with **exactly 6 bytes of
   "data"**. But a "door closed" reply carries **no data** — 0 bytes.
4. **The cause:** on a network cable, very short messages are padded with filler bytes up to a
   minimum size (an Ethernet frame must carry at least 46 bytes). The dataset's measuring tool
   counted that **filler as data**. So in the dataset, a closed-door reply = 6 bytes.
5. The model had learned *"a reply of exactly 6 bytes = port scan"*. Our engine measured the
   honest size (0 bytes), so the model never recognised a scan.
6. **The fix:** we changed our engine to measure sizes the same way the dataset's tool did
   (counting the filler) — one formula in `feature_extractor.py`. **The model itself was not
   changed or retrained.**
7. **Result: 600 of 600 probes detected as PortScan**, all at 90%+ confidence. Normal traffic was
   unaffected: 650 of 650 normal conversations stayed Benign.

### The side effect and the safety rule

After the fix, **one** normal refused connection looks exactly like **one** scan probe. So one
accidental connection could have got someone blocked. That is why we added the rule *"the model
alone may block only after 3 attack conversations from the same address within 10 seconds"*.
Tested: 1 stray connection → alert only, not blocked; a real scan → blocked from the 3rd probe.

### Why it matters (say this to the examiner)

> "A model is only as good as the match between how its training data was measured and how the
> live system measures. The dataset score of 99.9% for port scans would have been worth zero
> live if we hadn't found this."

### How it was proved and how to prove it live

- Recorded in `training/TRAINING_LOG.md`, entries 11 (the problem), 12 (the fix and result) and
  15 (the re-run script). The code change is commit `618f615`.
- There are unit tests for the measuring rule in `test_features.py`
  (`test_parse_bare_syn_counts_short_frame_padding_like_the_dataset` and others).
- Live: `python python-engine/tools/check_port_scan.py` (14 s). It builds the 600 probes plus 130
  normal conversations, runs them **with the old measuring rule** ("before") and **with the
  current rule** ("after"), and prints 0 of 600 → 600 of 600.
- Honest note: the script creates fresh packets of the same kind, not the exact packets of
  13 October, and its normal-traffic check is smaller (130 instead of 650 conversations).

---

## 12. How the project was tested

### The basis: what we tested against

| What | Against what | Why it is fair |
|---|---|---|
| The model | 184,679 test conversations hidden during training | The model never saw them, so it can't have memorised them. Exact copies were removed first, so no exam question also appeared in the study material. |
| False alarms | 1,553,034 normal conversations never used at all | A second, much bigger exam of only normal traffic. |
| Excluded attacks | Web attacks, Infiltration, Heartbleed | To confirm, honestly, that the model does **not** detect them (0–4.8%, log entry 9). |
| Targets set beforehand | Accuracy ≥ 95%, macro F1 ≥ 0.90, false alarms ≤ 0.5% | Fixed before testing; all met (99.56%, 0.947, 0.247%). |
| The code | 182 automatic tests | Each rule and decision checked with exact inputs. |
| The whole engine | Synthetic attacks (built packets) and a live run | Checks that all the parts work together. |

### Tools used

| Tool | Used for |
|---|---|
| **pytest** 9.1.1 | Running the 182 automatic tests |
| **scikit-learn** metrics | Accuracy, precision, recall, F1, confusion matrix |
| **Jupyter notebook** + pandas, NumPy, matplotlib | Training, evaluation, the confusion matrix picture |
| **Scapy** | Building fake attack packets for testing |
| `verify_model.py` | Unseen normal traffic and excluded attacks |
| `check_test_set.py` | Re-scoring the test set |
| `check_port_scan.py` | Re-running the port-scan fix |
| `simulate_attack.py` | Fake attacker for the live test and demo |
| `fake_firestore.py` | A pretend database, so tests run without the internet |
| **SHA-256** file fingerprint | Proving re-training gives a byte-identical model |
| **netsh / PowerShell** | Checking that firewall rules were really created and removed |

### Types of tests

| Type | What we did |
|---|---|
| **Unit tests** | 182 small automatic checks (list below) |
| **Integration tests** | Engine + database + AI + audit log together, with the pretend database |
| **Model evaluation** | The 184,679-flow test set |
| **Validation on unseen data** | 1.55 million normal conversations; excluded attack types |
| **Functional / system tests** | Built attack scenarios through the real engine code (log entries 11–12) |
| **Boundary tests** | Values exactly at each limit (e.g. 100 vs 101 SYNs), invalid addresses, broken requests |
| **Reliability / fault tests** | Database down, AI down, bad AI replies, full queues → the engine keeps working |
| **Security tests** | A viewer, or an old/expired request, cannot unblock an address |
| **Regression test** | The same packets before and after the port-scan fix |
| **Reproducibility test** | Re-training gave an identical model file (same SHA-256) |
| **Portability test** | The model loads in a second Python setup (log entry 10) |
| **Live test** | Real engine on a real laptop (log entry 13) |
| **Manual UI test** | The website in demo mode |

### The 182 automatic tests, file by file

All in `python-engine/tests/`.

| File | Tests | What they check (examples) |
|---|---|---|
| `test_features.py` | 28 | Packets in both directions form one conversation; conversations close on FIN/RST, silence or time limit; the 19 numbers come out right; the padding rule |
| `test_classifier.py` | 8 | The model loads and matches the feature list; gives the same answer one-by-one and in batches; evidence lists the right features |
| `test_rules.py` | 11 | SYN flood fires above 100 in 2 s and not on slow SYNs; port scan counts different doors; cooldown; senders counted separately; memory stays bounded |
| `test_detector.py` | 38 | Every row of the decision table; whitelist always wins; detect-only never touches the firewall; the 3-in-10-seconds rule; the 70% rule; repeated alerts are grouped |
| `test_blocker.py` | 27 | Whitelisted addresses are never blocked; invalid input never reaches netsh; no duplicate rules; unblocking works |
| `test_ai.py` | 33 | Only details (never packet contents) are sent to the AI; bad AI replies are rejected; offline text when the AI is down; rate limit |
| `test_firebase_client.py` | 23 | Saving never freezes the engine; admin unblock removes the rule and logs it; non-admin or old requests are refused |
| `test_sinks.py` | 10 | Each detection is saved, explained and (if blocked) audited |
| `test_main.py` | 4 | `--block` and `--detect-only` start options |
| **Total** | **182** | |

---

## 13. Live demo in front of the examiner

### Before the evaluation (do this the day before)

- [ ] Use **Tanishka's laptop** — it has the dataset, the Firebase key (`serviceAccountKey.json`), the AI key (`.env`) and the right Python.
- [ ] Npcap is installed; Node.js is installed (`npm install` already done in `frontend/`).
- [ ] Run all four proof commands once (Step 1 below) to be sure they work.
- [ ] Prefer a **phone hotspot** over college Wi-Fi for the live engine and simulator.
- [ ] Have these open in VS Code: `training/train_cicids2017.ipynb`, `training/TRAINING_LOG.md`, `training/reports/model_v1.md`, `python-engine/config.py`.
- [ ] Know the admin login for the website.

The Python to use is Miniconda's. In every PowerShell window, first set:

```powershell
$py = "C:\Users\Tanishkaa\miniconda3\python.exe"
cd "C:\Users\Tanishkaa\OneDrive\Desktop\Mini_Project\NetSentinel-Network-Packets-Detection-and-Prevention\New_Mini_Project"
```

### Step 1: prove the numbers (about 2 minutes, any normal PowerShell)

| Say | Run | Point at |
|---|---|---|
| "All 182 tests pass." | `cd python-engine; & $py -m pytest -q; cd ..` | `182 passed` |
| "This re-scores our saved model on the hidden test set — no retraining." | `& $py training/check_test_set.py` | `accuracy 0.9956`, `macro avg … 0.9472`, recall column |
| "False alarms on 1.55 million normal flows it never saw." | `& $py training/verify_model.py` | `3,833 (0.247%)` and `>= 0.70: 2,498 (0.161%)` |
| "Our port-scan discovery: 0 of 600 before, 600 of 600 after." | `& $py python-engine/tools/check_port_scan.py` | the last 4 lines |

### Step 2: show the live engine (about 3 minutes)

Needs **two PowerShell windows opened as Administrator** (right-click → Run as administrator).
Set `$py` and `cd` in both.

**Window 1 — start the engine with blocking on:**

```powershell
cd python-engine
& $py main.py --block
```

Wait for `[MAIN] Mode: BLOCKING (model confidence >= 0.9)` and `[MAIN] Starting packet capture...`.

**Window 2 — run the fake attacker:**

```powershell
cd python-engine
& $py simulate_attack.py
```

It prints three lines like `[+] portscan 60 packets from 198.51.100.42 -> expect PortScan`.

**Back in window 1** you should see, within seconds, lines like these (shortened; there is one
`[BLOCKED]` line per attacker address):

```
[BLOCKED] 198.51.100.42 … Windows Firewall rule created: 'CyberSentinel Block 198.51.100.42'
[THREAT] 198.51.100.42 -> <this laptop's IP> | PortScan | trigger=rule action=blocked conf=None
[THREAT] 198.51.100.66 -> … | SynFlood  | trigger=rule action=blocked conf=None
[THREAT] 198.51.100.77 -> … | IcmpFlood | trigger=rule action=blocked conf=None
```

`trigger=rule` means a counting rule caught it; `conf=None` means the model wasn't needed for
this decision.

**Window 2 — prove the firewall rule is real:**

```powershell
Get-NetFirewallRule -DisplayName 'CyberSentinel Block *' | Select-Object DisplayName
```

**Say:** "The addresses 198.51.100.x are reserved for documentation — they never exist on a real
network, so the demo can't block anyone real. The simulator runs on this same laptop; a test from
a second computer is our next step."

### Step 3: show the website (optional, 2 minutes)

A third, normal PowerShell window:

```powershell
cd frontend
npm run dev
```

Open http://localhost:5173 →
- **View Demo** (`/demo`): the replay of 84 recorded detections — no login needed.
- **Sign in** → the live dashboard shows the detections from Step 2. As admin, click **Unblock** on a blocked row; the engine removes the firewall rule (run the `Get-NetFirewallRule` command again to show it is gone). Click **Explain** to show the AI's explanation.

### Step 4: clean up

Stop the engine with **Ctrl+C**. Remove any demo blocks (Administrator PowerShell):

```powershell
Remove-NetFirewallRule -DisplayName 'CyberSentinel Block *'
```

### If something goes wrong

| Problem | What to do |
|---|---|
| `Permission denied` / no packets captured | The window is not Administrator. Re-open as Administrator. |
| `ModuleNotFoundError` | You used the wrong Python. Use `& $py …`, not `python`. |
| `Expected 8 CSV files` | You are not on Tanishka's laptop, or the dataset folder is missing. |
| No detections after the simulator | Wait 10 seconds; check the engine window shows `Starting packet capture`. If still nothing, show the proof scripts and the log entry 13 instead. |
| Website shows "engine offline" | The engine sends a heartbeat once a minute; wait a minute after starting it. |
| No internet | The engine still detects and blocks; only the website and AI need internet. The proof scripts work offline. |

---

## 14. What we must not claim

Saying these honestly makes us more credible, not less.

- **99.56% is on the CICIDS2017 test set** (a lab network), not on real-world traffic. On another network the model will make more mistakes; that's why rules and thresholds back it up.
- **The live test used a simulated attacker on the same laptop.** Real attacks from a second computer have not been tested yet.
- **In the live test, the counting rules caught the attacks, not the model** (the simulator's packets are a shape the model doesn't know). The model's port-scan detection was shown with built packets (Part 11).
- **Botnet detection is weak:** 59.6%, and 50.4% once the 70% rule is applied.
- **Web attacks, Infiltration and Heartbleed are not detected.**
- **Speed, CPU and memory under heavy live traffic were not measured.**
- **The demo page is a replay**, and it says so on screen.

---

## 15. Likely examiner questions

**Q: Where does the 99.56% come from?**
Our own experiment. We split CICIDS2017 80/20, trained on 80%, and tested on the 184,679
conversations the model never saw: 183,875 correct. Recorded in the notebook and training log;
I can re-calculate it now with `check_test_set.py`.

**Q: Isn't 99.56% suspiciously high?**
It is high because the test data comes from the same lab as the training data. We removed exact
duplicates so no test row was seen in training, and the 1.55 million unseen normal flows gave the
same false-alarm rate (0.247% vs 0.238%), so it's not luck. But real networks will be harder —
we say so openly.

**Q: Why CICIDS2017 and not NSL-KDD?**
NSL-KDD is based on 1999 traffic. Our first prototype used a downloaded KDD-style model and it
called normal web traffic "attack" (log entry 1). CICIDS2017 is modern, labelled, and gives flow
features we can compute live.

**Q: Why Random Forest?**
Top accuracy on this kind of data in research, no scaling needed, a confidence for every answer
(needed for our 70% and 90% rules), and fast enough to judge every conversation live.

**Q: What is a flow, and when does it end?**
All packets between the same two addresses and ports. It ends on FIN or RST, after 15 seconds of
silence, after 120 seconds, or when 50,000 are open.

**Q: Why 19 features?**
They describe behaviour (sizes, counts, timing). Flag counts were broken in the dataset; window
size and port scored higher only by recognising the lab's own machines.

**Q: Why is Botnet recall low? Why not fix it with class weighting?**
Botnet traffic looks like normal browsing, and there were only ~1,900 examples. Weighting raised
recall to 0.97 but precision collapsed to 0.12 — most alarms would be false.

**Q: Why rules AND a model?**
Rules react instantly to floods and fast scans, and catch floods the model never learned. The
model catches things rules can't, like a slow scan below the rule's 20-port limit (log entry 12:
12 ports at 2 per second was blocked from the 3rd probe by the model alone).

**Q: Why 70% and 90%?**
70%: live, normal downloads got 36–69% "DoS" verdicts; ignoring them cut false alarms by a third.
90%: on the test set it cuts wrongly blocked normal flows from 236 to 83 per 100,000 while still
blocking 98.66% of attacks.

**Q: How do you avoid blocking yourself?**
The whitelist: this laptop's addresses, the gateway, DNS, loopback and multicast are never
blocked. Invalid addresses count as whitelisted. Tested in `test_blocker.py`.

**Q: What if the internet or the cloud is down?**
Detection and blocking continue; saving and AI calls run on separate threads, and failures are
logged and skipped. Without the AI, a pre-written explanation is used. Tested in `test_ai.py` and
`test_firebase_client.py`.

**Q: Does the AI see our data?**
Only the detection details (attack type, confidence, addresses, ports, evidence) — never packet
contents. Tested (`test_request_carries_metadata_only`).

**Q: How does Unblock work?**
An admin clicks Unblock → the website writes a request into Firestore → the engine (listening)
checks the requester is an admin and the request is under 5 minutes old → removes the firewall
rule → records it in the audit log.

**Q: What does "0 to 600 of 600 probes" mean?** — Part 11.

**Q: Did you test on real attacks?**
On one laptop with a simulated attacker: real capture, real firewall rule, real remote unblock.
A second machine is our next step.

**Q: Can it run on Linux?**
Detection yes (Scapy works on Linux); blocking no — it uses Windows Firewall commands. Linux
support (iptables) is future work.

**Q: Is the result reproducible?**
Yes. Fixed seed 42; re-running the notebook gave a byte-identical model file (same SHA-256
fingerprint, log entry 7).

---

## 16. Where everything is

| File | What it is |
|---|---|
| `training/train_cicids2017.ipynb` | Training notebook, with all outputs saved |
| `training/TRAINING_LOG.md` | Diary of every experiment (entries 1–15) |
| `training/reports/model_v1.md` | The model report (all numbers) |
| `training/reports/model_v1_confusion_matrix.png` | The confusion matrix picture on the poster |
| `training/check_test_set.py` | Proof: accuracy, F1, recall, 70% effect |
| `training/verify_model.py` | Proof: false alarms on unseen normal traffic |
| `python-engine/tools/check_port_scan.py` | Proof: 0 → 600 of 600 probes |
| `python-engine/tests/` | The 182 automatic tests |
| `python-engine/config.py` | All thresholds and time windows |
| `python-engine/simulate_attack.py` | Fake attacker for the live demo |
| `README.md` | Setup and running instructions |
