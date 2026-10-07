# Repository Scan Analysis: CyberSentinel

This document provides an overview of the system based on a full repository scan, outlining the APIs used, working functionalities, pending features, and attack simulation methods.

## 1. List of All APIs & Libraries Used

Based on the codebase analysis, the following APIs and core libraries are utilized to build the system:

**Backend (Python Engine)**
*   **Scapy API:** For real-time network packet sniffing and lower-layer packet parsing (`sniffer.py`).
*   **Scikit-learn API:** For Machine Learning feature extraction, data scaling (`StandardScaler`), and model inference using a pre-trained Random Forest model (`classifier.py`).
*   **Windows Firewall CLI API (`netsh`):** Interfaced via Python's `subprocess` module to dynamically add/remove inbound blocking rules (`blocker.py`).
*   **Python built-in HTTP Server API (`http.server`):** Used to implement a Server-Sent Events (SSE) stream server for zero-latency IPC (`server.py`).
*   **Firebase Admin SDK API:** For securely connecting to Firestore and logging threat events and statistics (`firebase_client.py`).

**Frontend (React/Vite)**
*   **Firebase Client SDK API:** To subscribe to real-time database snapshots (`onSnapshot`) for instant UI updates.
*   **Browser EventSource API:** For receiving the real-time SSE stream pushed from the Python engine (`useLiveEngine.js`).
*   **Recharts API:** For visualizing protocol distributions in a donut chart (`ProtocolChart.jsx`).
*   **Vis-Network API:** For rendering a dynamic, physics-based, interactive network topology graph of attackers and targets (`TopologyGraph.jsx`).
*   *Note on Gemini API:* The "Gemini AI Threat Analysis" is currently simulated in the frontend (`GeminiPanel.jsx`) using a static knowledge base (`ATTACK_EXPLANATIONS`) rather than a live external Google Gemini API call.

---

## 2. All of the Functionalities Working

The following core features of the Intrusion Prevention System (IPS) are fully implemented and operational:

*   **Real-time Network Sniffing:** Capturing live inbound packets directly from the network interface.
*   **Traffic Aggregation & Feature Extraction:** Grouping packets into a 3-second window (or 30 packets per IP) and calculating 21 specific statistical features (based on the NSL-KDD dataset).
*   **ML-Based Threat Classification:** Running the feature vectors through a Random Forest model to detect 20 different attack categories (e.g., portsweep, neptune, smurf, nmap).
*   **Active Intrusion Prevention (Auto-blocking):** Automatically invoking Windows Firewall rules to block an attacker's IP upon threat detection.
*   **Zero-latency IPC (SSE):** Bridging the Python detection engine with the React dashboard via a local Server-Sent Events stream on port 5000.
*   **Interactive Command Center Dashboard:**
    *   Live Key Performance Indicators (Total Packets, Total Attacks, Blocked IPs).
    *   Real-time threat log table displaying attack vector, status, and IP details.
    *   Dynamic network topology graph showing attack vectors and nodes in real-time.
    *   Interactive "Unblock" action that instantly removes the firewall rule via an API call to the Python server.
    *   Plain-English AI Threat explanations presented in a sliding drawer (`GeminiPanel`).

---

## 3. Functionalities Yet to be Added (Based on System Architecture)

Based on the proposed tech stack (`proposed_tech_stack.md`) and architectural diagrams, the following functionalities are planned but not yet implemented:

*   **Authentication & Authorization:** Implementing Firebase Authentication to secure sensitive areas of the application, ensuring that only authorized personnel can access network traffic data or modify blocker rules.
*   **Dedicated Admin Panel:** A secure interface (Role-Based Access Control - RBAC) dedicated to administrators to manage firewall rules, view historical threat logs, and adjust the ML engine's sensitivity.
*   **Live Gemini LLM API Integration:** Replacing the static `ATTACK_EXPLANATIONS` dictionary in `GeminiPanel.jsx` with actual live API calls to Google's Gemini LLM to generate dynamic, context-aware threat narratives.
*   **Robust Backend Framework:** Transitioning the lightweight built-in `http.server` to a robust framework like **Python FastAPI** or **Node.js (Express)** to handle more complex admin actions and API routing securely.
*   **Historical Data & Pagination:** Expanding the Firebase integration beyond live stats/threats to store historical logs, requiring pagination and advanced querying on the frontend.

---

## 4. How Can We Simulate Various Kinds of Attacks

The repository currently includes a `simulate_attack.py` script that utilizes Scapy to craft and send packets, effectively simulating an attack. Here is how you can use and extend it to simulate various attacks:

**1. Simulating a Stealth Port Scan (Portsweep / Nmap)**
*   **Current Setup:** Run `python simulate_attack.py`.
*   **How it works:** The script sends a rapid burst of 40 TCP SYN packets (flags="S") to sequentially increasing ports (20 to 60) on your local IP from a spoofed attacker IP (`198.51.100.42`). This mimics an Nmap stealth scan and triggers the `portsweep` or `nmap` classification.

**2. Simulating a SYN Flood Attack (Neptune / DoS)**
*   **How to simulate:** Modify the `simulate_attack.py` script to send hundreds or thousands of TCP SYN packets to a single specific port (e.g., port 80 or 443) on the target machine without completing the handshake. 
*   **Scapy Implementation:** Use a loop to continuously send `IP(src=spoofed_ip, dst=target_ip) / TCP(dport=80, flags="S")`. Randomizing the `src` IP slightly can make it a Distributed DoS (DDoS) simulation.

**3. Simulating a Smurf Attack (ICMP Amplification DoS)**
*   **How to simulate:** This attack relies on spoofing the source IP as the victim's IP and sending ICMP Echo Requests (pings) to the network's broadcast address.
*   **Scapy Implementation:** Craft a packet like `IP(src=target_ip, dst="192.168.1.255") / ICMP()`.

**4. Simulating Password Guessing (Brute-Force)**
*   **How to simulate:** Send a high volume of complete TCP connections (3-way handshake) or login payloads to a specific service port, like port 22 (SSH) or 21 (FTP).
*   **Scapy Implementation:** While Scapy can do this, it's often easier to simulate brute-force by opening standard sockets in a tight loop targeting port 22 from the attacker script, mimicking the high frequency of connection attempts typical of a dictionary attack (`guess_passwd`).
