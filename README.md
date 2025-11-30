# 🛡️ Simple Intrusion Detection System (IDS)

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Scapy](https://img.shields.io/badge/Scapy-2.4%2B-orange)
![Flask](https://img.shields.io/badge/Flask-2.0%2B-green)
![License](https://img.shields.io/badge/License-MIT-green)

A lightweight Intrusion Detection System (IDS) built in Python that parses and enforces **Snort Rules**. It monitors network traffic in real-time and displays alerts on a web dashboard when malicious patterns are detected.

## 🧐 The Problem

Traditional IDS tools like Snort are powerful but can be difficult to install and configure, especially on Windows. Understanding *how* they work is often hidden behind complex binaries.

## 💡 The Solution

This project implements a **Custom IDS Engine** that:
1.  **Parses Snort Rules**: Reads standard syntax (e.g., `alert tcp any any -> any 80`).
2.  **Sniffs Traffic**: Uses Scapy to capture packets.
3.  **Matches Patterns**: Compares packets against loaded rules (Protocol, IP, Port).
4.  **Alerts**: Logs detections to a real-time web dashboard.

## 🚀 Features

- **Snort-Compatible**: Write rules in standard Snort syntax in `local.rules`.
- **Real-Time Dashboard**: Live feed of triggered alerts.
- **Traffic Generator**: Includes `traffic_gen.py` to simulate attacks (Ping, HTTP, Port 4444) for testing.
- **Customizable**: Easily add new rules to detect specific threats.

## 🛠️ Installation

### Prerequisites
- **Python 3.8+**
- **Npcap** (Windows): Required for packet sniffing.
- **Admin Privileges**: Required to capture network traffic.

### Steps

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/CyberShuriken/simple-ids.git
    cd simple-ids
    ```

2.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## 💻 Usage

**Note:** You must run the IDS as **Administrator**.

1.  **Start the IDS**:
    ```bash
    python app.py
    ```

2.  **Open Dashboard**:
    Go to `http://localhost:5000`. You will see the active rules loaded.

3.  **Simulate Traffic** (Open a new terminal):
    ```bash
    python traffic_gen.py
    ```

4.  **Watch the Dashboard**:
    You will see alerts for "ICMP Ping", "HTTP Traffic", and "Suspicious Port 4444".

## 🧠 Skills Demonstrated

- **Network Security**: Understanding IDS signatures and packet analysis.
- **Regex**: Parsing complex rule syntax.
- **Scapy**: Advanced packet manipulation and sniffing.
- **Full-Stack Python**: Building a backend engine with a frontend dashboard.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
