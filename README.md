# 🛡️ CyberSentinel — ML-Based Network Intrusion Detection & Automated Prevention System

CyberSentinel is a real-time **Intrusion Prevention System (IPS)** that combines live Scapy packet sniffing, Random Forest Machine Learning (trained on 21 NSL-KDD features across 20 attack categories), active Windows Firewall (`netsh advfirewall`) blocking, and a modern React 19 cybersecurity dashboard with Gemini AI Threat Analysis.

---

## 🏗️ System Architecture

```
[ Incoming Network Packets ]
             │
             ▼
   [ python-engine/sniffer.py ]          ← Scapy packet capture (dst == my_ip)
             │
             ▼ (3s / 30-packet flow window)
   [ feature_extractor.py ]               ← 21 NSL-KDD statistical features
             │
             ▼
   [ classifier.py ]                      ← Random Forest ML model inference
             │
   ┌─────────┴─────────┐
   ▼                   ▼
[ If Normal ]     [ If Attack Detected ]
Log flow           ├── blocker.py         ← Active Windows Firewall block (netsh)
                   ├── server.py          ← Real-Time SSE Event Stream (port 5000)
                   └── firebase_client.py ← Firestore Document Write
                               │
                               ▼
                [ frontend/ (React 19 + Vite) ]
                ├── StatCards, ProtocolChart, ThreatTable
                ├── vis-network Interactive Topology Graph
                └── Gemini AI Threat Analyst Drawer & Chat Page
```

---

## 🛠️ Prerequisites

Before running the project, ensure you have:
1. **Python 3.10+** (Conda/Miniconda recommended)
2. **Node.js 18+** & `npm`
3. **Windows OS** (required for `netsh advfirewall` active blocking)
4. *(Optional but recommended)* **[Npcap for Windows](https://npcap.com/#download)** installed with *"WinPcap API-compatible Mode"* enabled.

---

## ⚡ Quick Start & Execution Guide

### Step 1: Clone Repository & Setup Frontend

```powershell
# Clone the repository
git clone https://github.com/TanishkaaGharwade/New_Mini_Project.git
cd New_Mini_Project/frontend

# Install frontend dependencies
npm install

# Start Vite React dev server
npm run dev
```
Open **[http://localhost:5173](http://localhost:5173)** in your browser.  
*(Top status badge will display `● WAITING FOR ENGINE (RUN MAIN.PY)` until Python engine starts).*

---

### Step 2: Run Python Detection & Prevention Engine

Open a **new PowerShell / Command Prompt window as Administrator**:

```powershell
cd New_Mini_Project/python-engine

# Install Python requirements
pip install -r requirements.txt

# Run main engine as Administrator
python main.py
```

*Or with explicit Conda Python path:*
```powershell
C:\Users\<YourUsername>\miniconda3\python.exe main.py
```

*(Once running, your dashboard status badge will instantly light up green: **`● LIVE MONITORING ACTIVE`**).*

---

### Step 3: Test & Simulate an Attack (Demo)

Open a **second terminal window** and run our single-click attack simulator:

```powershell
cd New_Mini_Project/python-engine
python simulate_attack.py
```

---

## 🎯 What Happens During the Demo:

1. **Python Console Output**:
   ```text
   [ATTACK] 198.51.100.42 → 192.168.1.4 | PORTSWEEP | 40 pkts | TCP
   [BLOCK] Firewall rule added: block 198.51.100.42
   [+] Broadcasted event to connected React Dashboard
   ```
2. **React Dashboard Update**:
   - **Attacks Detected** & **IPs Blocked** counters increment live.
   - **Network Topology Graph** dynamically adds node `198.51.100.42 [portsweep]` with a red dashed attack vector.
   - **Real-Time Threat Log** adds a new red row displaying attack vector, status `BLOCKED`, and action buttons.
3. **AI Threat Explanation**:
   - Click the **`Explain`** button on any threat row to open the **Gemini AI Analyst** drawer for plain-English attack narratives and countermeasures.
4. **Interactive Unblock**:
   - Click the **`Unblock`** button on a blocked row to send a `POST /unblock` request to `server.py`, which executes `netsh advfirewall firewall delete rule` and removes the firewall block in real time.

---

## 📁 Repository Structure

```
New_Mini_Project/
├── python-engine/
│   ├── main.py              # Engine entry point (wires sniffer, ML classifier, blocker, SSE server)
│   ├── sniffer.py           # Scapy packet capture loop with flow aggregation window
│   ├── feature_extractor.py # Layer 1 parser + Layer 2 21 NSL-KDD feature vector calculation
│   ├── classifier.py        # Random Forest model inference wrapper (majority voting)
│   ├── blocker.py           # Windows Firewall netsh rule creation & unblock API
│   ├── server.py            # Built-in HTTP SSE server on port 5000 for zero-config React IPC
│   ├── firebase_client.py   # Firestore document logger
│   ├── simulate_attack.py   # Single-click demo attack generator
│   ├── config.py            # Parameters (flow window, never-block safeguards)
│   ├── requirements.txt     # Pinned Python dependencies
│   └── models/
│       ├── model.pkl        # Trained Random Forest classifier
│       └── preprocessor.pkl # Scaler & ColumnTransformer pipeline
│
└── frontend/
    ├── index.html           # HTML5 root with Google Fonts & SEO meta
    ├── vite.config.js       # Vite configuration with Tailwind v4
    ├── package.json         # Node.js dependencies
    └── src/
        ├── main.tsx         # React entry point with ResizeObserver error handler
        ├── App.jsx          # Root component
        ├── index.css        # Glassmorphism dark cybersecurity design system
        ├── components/
        │   ├── Navbar.jsx        # Top bar with live connection badge & attack alert
        │   ├── Sidebar.jsx       # 5-tab left navigation
        │   ├── StatCards.jsx     # Glassmorphism KPI cards
        │   ├── ProtocolChart.jsx # Recharts protocol distribution donut chart
        │   ├── ThreatTable.jsx   # Real-time threat log with attack badges & unblock action
        │   ├── TopologyGraph.jsx # vis-network force-directed attack graph
        │   └── GeminiPanel.jsx   # Gemini AI threat explanation drawer
        ├── pages/
        │   ├── DashboardPage.jsx # Main Command Center page
        │   ├── ThreatsView.jsx   # Dedicated Threat Log page
        │   ├── TopologyView.jsx  # Dedicated Network Topology page
        │   ├── AIAnalystView.jsx # Dedicated Gemini AI Chat page
        │   └── SettingsView.jsx  # Engine & Firewall Config page
        └── hooks/
            └── useLiveEngine.js  # Real-time SSE hook (http://localhost:5000/events)
```

---

## ⚙️ Key Configuration Parameters (`python-engine/config.py`)

| Parameter | Default | Description |
|---|---|---|
| `FLOW_WINDOW_PACKETS` | `30` | Number of packets accumulated per IP before running ML inference. |
| `FLOW_WINDOW_SECONDS` | `3.0` | Maximum time window to accumulate flow statistics. |
| `NEVER_BLOCK_IPS` | `127.0.0.1`, `192.168.1.1` | Whitelisted IPs & gateways that are never blocked. |
| `NEVER_BLOCK_PREFIXES` | `13.107.`, `34.54.` | Microsoft/Google cloud subnets ignored for noise reduction. |

---

## 📜 License & Acknowledgments

- **Dataset**: Trained on NSL-KDD Network Intrusion Detection Dataset.
- **Reference Architectures**: Inspired by `Vanshika110/network-monitor-dashboard` & `Chanveasna-ENG/Network-Intrusion-Detection-and-Monitoring-Tool`.
