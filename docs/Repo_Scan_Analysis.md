# CyberSentinel — Comprehensive Repository Scan & System Status Report

**Date:** 13 October 2026  
**Repository:** `TanishkaaGharwade/New_Mini_Project`  
**Branch:** `main`  
**Purpose:** Full audit of the repository following the transition from legacy NSL-KDD prototype to the CICIDS2017 production architecture, tracking work completed across Part A, Part B, and Part C.

---

## 1. Executive Summary

CyberSentinel is an Autonomous Network Intrusion Detection & Prevention System (NIDS/IPS) tailored for Windows hosts. The project underwent a critical architectural pivot after diagnosing severe defects in the initial prototype (where unbounded feature counters caused all traffic to be misclassified as attacks, specifically `satan`).

The system architecture is divided across three core tracks:
1. **Part A (Detection Engine & Core Pipeline):** Packet capture, bidirectional flow tracking, 19 statistical CICIDS2017 features, Random Forest classifier (`model_v1.pkl`), rule-based rate anomaly detection, Windows Firewall (`netsh`) blocking, and replay simulation.
2. **Part B (Cloud Persistence, Security & AI Backend):** Firebase Authentication, Firestore threat/stats storage, role-based access control (Admin vs. Viewer), asynchronous `commands` firewall unblock listener, audit logging, and Groq LLM-powered incident explanations.
3. **Part C (Unified Dashboard, Replay Demo Mode & Deployment):** Dual-mode React 19 + Vite dashboard (Demo Mode via recorded replay vs. Live Mode via Firestore), interactive network topology, protocol analytics, evidence-based AI explanation drawers, admin controls, landing page, and Vercel cloud deployment.

---

## 2. Repository Structure & Artifact Scan

```
New_Mini_Project/
├── .gitignore                          # Configured for secrets, node_modules, training data
├── README.md                           # Needs update (currently describes legacy NSL-KDD system)
├── system_arch.mmd                     # Mermaid diagram (needs update for new architecture)
├── packet_exec_and_response_flow.mmd   # Mermaid packet flow (needs update)
│
├── docs/                               # System specifications & designs
│   ├── SRS.md                          # Software Requirements Specification (needs update)
│   ├── Repo_Scan_Analysis.md           # This document (comprehensive scan)
│   ├── Algorithm_Design.md             # Algorithm mathematical formulations
│   ├── proposed_tech_stack.md          # Tech stack overview
│   └── presentation.md                 # Project presentation deck
│
├── part_c/                             # Implementation specifications & plans
│   ├── PART_C_DASHBOARD_DEPLOY.md      # Detailed step-by-step specification for Part C (M7, M8, M9 UI, M10)
│   ├── docs/
│   │   ├── IMPLEMENTATION_PLAN.md      # Master blueprint (M0 through M10)
│   │   └── TEAM_WORK_SPLIT.md          # 3-person team split (Parts A, B, C)
│   └── training/
│       ├── DATASET.md                  # CICIDS2017 download & validation guide
│       ├── PREPROCESSING.md            # Data cleaning rules & feature definitions
│       └── README.md                   # Model version registry
│
├── training/                           # Active ML Training Pipeline
│   ├── train_cicids2017.ipynb          # Reproducible Random Forest training notebook
│   ├── features.json                   # Authoritative 19 feature definitions in order
│   ├── verify_model.py                 # Automated verification & false-positive checker
│   ├── TRAINING_LOG.md                 # Chronological log of model experiments
│   ├── requirements.txt                # ML training dependencies
│   └── reports/
│       └── model_v1.md                 # model_v1 performance metrics (Accuracy 0.9956, F1 0.9472)
│
├── python-engine/                      # Windows Host Detection Engine
│   ├── config.py                       # Engine thresholds (DETECT_ONLY, BLOCK_CONFIDENCE, etc.)
│   ├── sniffer.py                      # Scapy raw packet sniffer
│   ├── feature_extractor.py            # Bidirectional 5-tuple flow tracker & 19 feature builder
│   ├── classifier.py                   # Loads model_v1.pkl, returns label, confidence & evidence
│   ├── rules.py                        # Rate rules (SynFlood, PortScan, IcmpFlood)
│   ├── detector.py                     # Decision matrix (model + rules -> trigger & action)
│   ├── blocker.py                      # Windows Firewall CLI wrapper with subnet safety
│   ├── netinfo.py                      # Local IP & interface discovery
│   ├── replay.py                       # Offline PCAP / dataset flow replay & export tool
│   ├── server.py                       # Lightweight local SSE server
│   ├── sinks.py                        # Unified detection dispatcher
│   ├── main.py                         # Production multi-threaded engine orchestrator
│   ├── firebase_client.py              # Firestore integration (legacy schema present)
│   ├── simulate_attack.py              # Scapy test packet injector
│   ├── requirements.txt                # Pinned engine dependencies
│   ├── models/
│   │   ├── model_v1.pkl                # Trained Random Forest pipeline (CICIDS2017)
│   │   └── model_v1.meta.json          # Model metadata & hyperparameters
│   └── tests/                          # Automated unit test suite
│       ├── conftest.py
│       ├── test_blocker.py
│       ├── test_classifier.py
│       ├── test_detector.py
│       ├── test_features.py
│       ├── test_rules.py
│       └── test_sinks.py
│
└── frontend/                           # React 19 + Vite Dashboard
    ├── package.json                    # Scripts & dependencies (missing explicit react/react-dom entries)
    ├── vite.config.js                  # Vite configuration with React & Tailwind plugins
    ├── tsconfig.json                   # TypeScript config for Vite
    ├── index.html                      # App HTML entrypoint
    ├── public/
    │   ├── demo/
    │   │   └── replay.json             # 40 pre-recorded attack events generated by replay.py
    │   ├── favicon.svg
    │   └── icons.svg
    └── src/
        ├── main.tsx                    # React mounting root
        ├── App.jsx                     # Root router/component
        ├── index.css                   # Dark theme design system & variables
        ├── firebaseConfig.js           # Firebase app initialization
        ├── components/
        │   ├── Navbar.jsx              # Header status bar
        │   ├── Sidebar.jsx             # Navigation sidebar
        │   ├── StatCards.jsx           # KPI metrics cards
        │   ├── ProtocolChart.jsx       # Recharts protocol distribution donut
        │   ├── ThreatTable.jsx         # Live threat table & actions
        │   ├── TopologyGraph.jsx       # vis-network dynamic network graph
        │   └── GeminiPanel.jsx         # Legacy hardcoded explanation drawer
        ├── pages/
        │   ├── DashboardPage.jsx       # Master command center view
        │   ├── ThreatsView.jsx         # Dedicated threat intelligence view
        │   ├── TopologyView.jsx        # Dedicated network topology view
        │   ├── AIAnalystView.jsx       # Interactive AI analyst chat view
        │   └── SettingsView.jsx        # System & engine parameters view
        ├── hooks/
        │   ├── useLiveEngine.js        # Local SSE event hook (localhost:5000)
        │   └── useFirestoreThreats.js  # Firestore subscription hook (legacy dummy fallback)
        └── data/
            └── dummyThreats.js         # Legacy mock data & 20 NSL-KDD badge classes
```

---

## 3. Detailed Component Audit: What is Done vs. What is Left

### 3.1 Part A: Detection Engine (`python-engine/` & `training/`)
**Owner:** Teammate A  
**Status: COMPLETED (~95% Complete)**

| Step | Task | Status | Notes / Artifacts |
|---|---|:---:|---|
| A0 / M0 | Safety & Repo Setup | **DONE** | `DETECT_ONLY = True` default; whitelist uses `ipaddress` subnet validation in `blocker.py`. |
| A1 / M1 | Capture & Flow Tracking | **DONE** | `feature_extractor.py` rewritten with bidirectional 5-tuple tracking, flow timeouts, FIN/RST expiration. |
| A2 / M1 | 19 Feature Extraction | **DONE** | Exact match to `training/features.json` and CICIDS2017 definitions in `PREPROCESSING.md`. |
| A3 / M2 | Model Training | **DONE** | `model_v1.pkl` trained on CICIDS2017 (Accuracy 0.9956, Macro F1 0.9472) across 6 classes: `Benign`, `DoS`, `DDoS`, `PortScan`, `BruteForce`, `Botnet`. |
| A4 / M3 | Rules Engine | **DONE** | `rules.py` implements SYN flood, Port scan, and ICMP flood rate detection. |
| A5 / M3 | Decision Engine | **DONE** | `detector.py` implements the decision matrix (`rule`, `model`, `both` triggers) and correlates evidence. |
| A6 / M4 | Firewall Hardening | **DONE** | `blocker.py` validates IPs, prevents duplicate rules, inspects existing Windows Firewall rules on boot. |
| A7 / M1-M4 | Unit Test Suite | **DONE** | 6 test suites in `python-engine/tests/` verifying blocker, classifier, detector, features, rules, and sinks. |
| A8 / M8 | Replay Tool & Demo Data | **DONE** | `replay.py` built; generated real offline predictions to `frontend/public/demo/replay.json`. |
| **Pending in Part A:** | Live real-world validation logging in `training/TRAINING_LOG.md` under prolonged live network traffic. |

---

### 3.2 Part B: Cloud, Authentication & AI Backend (`python-engine/` & Firebase)
**Owner:** Teammate B  
**Status: PENDING / INCOMPLETE (~20% Complete)**

*Note: While Part A is solid, Part B modules (M5, M6, M9 backend) have not yet been fully merged or committed into the repository.*

| Step | Task | Status | Current Reality in Codebase |
|---|---|:---:|---|
| B1 / M5 | Firestore Project & Admin Setup | **PARTIAL** | Firebase project created (`new-mini-project-ed9c6`), but secret keys not checked in (by design). |
| B2 / M5 | Firestore Security Rules | **PENDING** | `firestore.rules` file is **not yet created** in the repository. |
| B3 / M5 | Firestore Client Rewrite | **PENDING** | `python-engine/firebase_client.py` still contains legacy NSL-KDD field names (`attack_type`, `.rstrip(".")`, no evidence/explanation support). |
| B4 / M5 | Commands Listener (Unblock) | **PENDING** | `firebase_client.py` does not currently listen to the `commands` collection to trigger `blocker.unblock_ip()`. |
| B5 / M6 | Frontend Authentication Context | **PENDING** | `AuthContext.jsx` and `LoginPage.jsx` are **missing** from `frontend/src/`. |
| B6 / M6 | Admin Management & Audit Pages | **PENDING** | `UsersPage.jsx` and `AuditLogPage.jsx` are **missing** from `frontend/src/pages/`. |
| B7 / M9 | Groq AI Explanation Backend | **PENDING** | `python-engine/ai.py` is **missing**; engine does not yet call Groq API to annotate threat records. |
| B8 / M9 | Serverless Chat Endpoint | **PENDING** | `frontend/api/chat.js` is **not yet implemented**. |

---

### 3.3 Part C: Dashboard, Demo Mode & Deployment (`frontend/` & `docs/`)
**Owner:** User (Krisha)  
**Status: CURRENT FOCUS (Ready for Implementation)**

Part C delivers the operational face of the system. According to `part_c/PART_C_DASHBOARD_DEPLOY.md`, Part C is designed to be self-sufficient: it can run immediately with offline/sample data and the pre-generated `replay.json`, decoupling it from any unfinished Part B work.

Below is the complete status of the 14 Part C steps:

| Step | Module | Task Description | Status | What Needs to be Done |
|---|---|---|:---:|---|
| **C0** | Setup | Build verification | **PENDING** | Fix `package.json` (add explicit `react`, `react-dom`), clean TS build, verify `npm run build`. |
| **C1** | Data | Contract Sample Data | **PENDING** | Create `frontend/src/data/sampleThreats.json` with 15+ threat records matching the shared contract format. |
| **C2** | Architecture | Unified Data Hook | **PENDING** | Create unified interface `{ threats, stats, engineOnline, mode, requestUnblock }`; rewrite `useFirestoreThreats.js` and build `useDemoReplay.js`. |
| **C3** | Schema | Rename fields in components | **PENDING** | Replace `attack_type` with `label`, `blocked` with `action === 'blocked'`, remove `normal` checks across all components. |
| **C4** | Design | Modern Labels & Badges | **PENDING** | Create `src/data/labels.js` with metadata/colors for the 7 active attack classes; deprecate `dummyThreats.js`. |
| **C5** | UI | Threat Table & Filtering | **PENDING** | Add columns (Confidence, Trigger, Action status), multi-criteria filters, and IP search in `ThreatTable.jsx` & `ThreatsView.jsx`. |
| **C6** | Integration | Admin Unblock Workflow | **PENDING** | Enable unblock button only for `role === 'admin'` & `action === 'blocked'`; create Firestore `commands` doc with pending timeout. |
| **C7** | Navigation | Navbar, Sidebar & Settings | **PENDING** | Engine heartbeat indicator; Demo banner; user profile & role badge; clean settings referencing CICIDS2017 and model v1. |
| **C8** | AI Integration | Explanation Drawer & Chat | **PENDING** | Rename `GeminiPanel` -> `ExplanationPanel`; display structured explanation & evidence; eliminate all "Gemini" branding; connect chat view. |
| **C9** | Demo Mode | Interactive Demo Replay | **PENDING** | Implement `useDemoReplay.js` consuming `public/demo/replay.json` with timer, playback loop, and controls. |
| **C10** | Routing | URL Routing & Route Guards | **PENDING** | Configure `react-router-dom` in `App.jsx` for `/`, `/demo/*`, `/login`, `/app/*`, ensuring tabs persist on reload. |
| **C11** | Landing Page | Modern Public Showcase | **PENDING** | Build `LandingPage.jsx` with high-aesthetic hero, "View Demo" / "Sign In" actions, and system architecture briefing. |
| **C12** | Deployment | Vercel Deployment Setup | **PENDING** | Add `frontend/vercel.json` SPA rewrites and serverless `/api/chat.js` proxy. |
| **C13** | Polish | Cleanup & Responsiveness | **PENDING** | Delete unused template files (`counter.ts`, `style.css`), update `index.html` metadata, verify responsive layout. |
| **C14** | Documentation | Update Project Docs | **PENDING** | Update `README.md`, `SRS.md`, diagrams, and presentation to reflect the true CICIDS2017 + Groq architecture. |

---

## 4. The Shared Threat Record Contract

All Part C UI components adhere to this strict schema:

```json
{
  "id": "doc-uuid-string",
  "timestamp": "2026-10-13T09:30:00Z",
  "src_ip": "198.51.100.42",
  "src_port": 51544,
  "dst_ip": "192.168.1.20",
  "dst_port": 80,
  "protocol": "TCP",
  "label": "PortScan",
  "confidence": 0.97,
  "trigger": "both",
  "action": "blocked",
  "packet_count": 40,
  "evidence": [
    { "feature": "distinct ports in 5 s", "value": 38 },
    { "feature": "Flow Packets/s", "value": 2100.5 }
  ],
  "explanation": {
    "severity": "HIGH",
    "summary": "Stealth port reconnaissance probing open destination services.",
    "mechanism": "High rate of SYN packets sent to sequential destination ports without completing 3-way handshake.",
    "recommendation": "Inbound traffic from 198.51.100.42 isolated via Windows Firewall netsh rule.",
    "source": "ai"
  }
}
```

### Allowed Values Reference:
- **`label`:** `DoS`, `DDoS`, `PortScan`, `BruteForce`, `Botnet`, `SynFlood`, `IcmpFlood`
- **`trigger`:** `model`, `rule`, `both`
- **`action`:** `blocked`, `alert_only`, `detect_only`, `whitelisted`, `unblocked`
- **`explanation.source`:** `ai`, `offline`

---

## 5. Strategic Execution Roadmap for Part C

To make the system fully functional and ready for presentation and deployment:

```
[Phase 1: Foundation & Build Fix]
  ├── C0: Fix package.json & dependencies (react, react-dom)
  ├── C1: Create sampleThreats.json (15 comprehensive records)
  └── C4: Create labels.js & remove dummyThreats.js

[Phase 2: Unified Data & Demo Replay Engine]
  ├── C2 & C9: Implement useDemoReplay.js (reads public/demo/replay.json)
  └── C2: Modernize useFirestoreThreats.js with unified contract output

[Phase 3: Component Migration & Design Upgrade]
  ├── C3 & C5: Upgrade ThreatTable & ThreatsView (new columns, filtering, unblock)
  ├── C3: Upgrade StatCards, ProtocolChart, TopologyGraph
  ├── C7: Update Navbar (Heartbeat, Demo badge), Sidebar, SettingsView
  └── C8: Rename & overhaul ExplanationPanel (render evidence, remove Gemini branding)

[Phase 4: Routing, Pages & Auth Resilience]
  ├── C10: Setup react-router-dom in App.jsx (/, /demo/*, /login, /app/*)
  ├── Auth: Provide resilient AuthContext & LoginPage (works in demo/fallback & live Firebase)
  └── C11: Build premium LandingPage.jsx

[Phase 5: Deployment, Cleanup & Docs]
  ├── C12: vercel.json + /api/chat.js stub/integration
  ├── C13: Clean boilerplate & refine responsive design
  └── C14: Synchronize README.md, SRS.md, and system diagrams
```
