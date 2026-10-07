# Proposed Tech Stack

This document outlines the proposed technology stack for the Network Traffic Monitoring and Analysis project, taking into account the future addition of an admin panel and real-time backend monitoring interfaces.

## 🎨 Frontend
The frontend will serve as the user interface for both regular users and administrators to monitor network traffic, view alerts, and manage the system.

*   **Languages & Frameworks:** React with TypeScript
*   **Build Tool:** Vite (for fast, optimized development and builds)
*   **Styling:** Tailwind CSS (for rapid, responsive UI development)
*   **Data Visualization:**
    *   **Recharts:** For statistical graphs and time-series data of network traffic.
    *   **Vis-Network:** For dynamic, interactive network topology maps.
*   **Routing:** React Router DOM (for navigating between dashboards, admin panels, and settings)
*   **Icons:** Lucide React

## ⚙️ Backend & Processing
The backend is split into the packet processing engine (which does the heavy lifting) and the data syncing layer.

### Processing Engine (Network & ML Layer)
*   **Language:** Python
*   **Packet Sniffing & Manipulation:** Scapy (for capturing real-time network traffic)
*   **Machine Learning:** Scikit-learn, NumPy, Pandas, Joblib (for feature extraction, training, and classifying malicious vs. benign traffic)
*   **Environment Management:** python-dotenv

### Backend API / Integration Layer (Connecting Frontend & Processing)
Currently, Firebase is used to bridge the Python processing engine and the React frontend. If a dedicated backend server is needed in the future for complex admin actions, a framework like **Python FastAPI** or **Node.js (Express)** could be introduced.
*   **Current Bridge:** Firebase Admin SDK (Python) sending real-time data to Firebase Client SDK (React).

## 🗄️ Database
*   **Primary Database:** Firebase Realtime Database or Cloud Firestore.
    *   *Why:* Perfect for a network monitoring tool because it pushes live traffic updates and security alerts instantly to the React frontend without requiring manual polling.

## 🔐 Authorization & Authentication
*   **Service:** Firebase Authentication
    *   *Features:* Will be used to secure the Admin Panel, ensuring only authorized personnel can view sensitive network traffic data or modify blocker rules. Supports email/password, OAuth, and Role-Based Access Control (RBAC).

## 🛠️ Other Tools & Interfaces
*   **Version Control:** Git & GitHub
*   **Architecture Mapping:** Mermaid (`.mmd` files for system flow and packet execution architecture)
*   **Package Managers:** `npm` (Frontend) and `pip` (Backend)
