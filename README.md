# Automated Network Packet Sniffer & Protocol Analyzer

A Python-based network traffic analysis tool built with **Scapy** for live packet capture, protocol identification, traffic analysis, anomaly detection, and automated reporting.

The project was developed in an Ubuntu virtual machine and validated using **Wireshark** and **Nmap**. Ansible was used to automate the project environment setup.

---

## Overview

The analyzer provides a lightweight workflow for observing and investigating network traffic:

```text
Live Traffic
     │
     ▼
Packet Capture
     │
     ▼
Protocol & Traffic Analysis
     │
     ▼
Anomaly Detection
     │
     ├──────────────► capture.pcap
     │
     ▼
Automated Report
     │
     ▼
Wireshark Investigation
```

### Key Capabilities

* Live packet capture using Scapy
* TCP, UDP, ICMP, ARP and DNS identification
* Host communication tracking
* TCP destination port analysis
* Rule-based anomaly detection
* PCAP generation for further investigation
* Automated traffic analysis reports
* Wireshark-based packet investigation
* Ansible-based environment setup

---

## Detection Capabilities

The analyzer implements four lightweight detection mechanisms:

| Detection             | Method                                                                                      |
| --------------------- | ------------------------------------------------------------------------------------------- |
| **TCP Port Scan**     | Detects multiple unique TCP destination ports contacted by the same source/destination pair |
| **ICMP Anomaly**      | Detects an ICMP traffic spike above a configured threshold                                  |
| **ARP Inconsistency** | Detects changes in the observed IP-to-MAC relationship                                      |
| **DNS Anomaly**       | Detects unusually high DNS request activity from a source                                   |

Detection thresholds are configurable directly in `analyzer.py`.

---

## Controlled Testing

A controlled TCP port scan was generated using Nmap:

```bash
nmap -sT -Pn -p 20-100 10.0.2.2
```

The analyzer successfully detected the test activity:

```text
TCP port scans : 1
```

The generated traffic was then investigated in Wireshark to verify the packet-level behavior.

---

## Results

A representative capture contained **402 packets**:

| Protocol | Packets |
| -------- | ------: |
| TCP      |     351 |
| UDP      |      12 |
| ICMP     |      10 |
| ARP      |       2 |
| DNS      |      10 |

### Detection Results

```text
TCP port scans : 1
ICMP anomalies : 0
ARP anomalies  : 0
DNS anomalies  : 0
```

The detected TCP port scan corresponds to the controlled Nmap test.

DNS is reported separately for analysis purposes while also being part of the UDP traffic count.

---

## Wireshark Investigation

The analyzer saves captured traffic as a PCAP file, which was subsequently analyzed in Wireshark.

### TCP Traffic Analysis

![TCP Traffic Analysis](screenshots/tcp-analysis.png)

Captured TCP traffic was inspected to verify source and destination addresses, port numbers, packet length, and TCP flags.

### TCP Port Scan Investigation

![TCP Port Scan Investigation](screenshots/port-scan-analysis.png)

TCP SYN packets generated during the controlled Nmap scan were examined to validate the port-scan detection.

The investigation focused on connection attempts with the **SYN flag set and ACK flag not set**.

### DNS Traffic Analysis

![DNS Traffic Analysis](screenshots/dns-analysis.png)

A captured DNS query was inspected to verify the source and destination addresses, UDP ports, and DNS query information.

---

## Automated Reporting

After packet capture is stopped, the analyzer generates:

```text
capture.pcap
analysis_report.txt
```

The automated report includes:

* Total packet count
* Protocol distribution
* Top TCP destination ports
* Top communicating hosts
* Anomaly detection results

This allows the captured traffic to be preserved as evidence while also producing a concise analysis summary.

---

## Automation with Ansible

Ansible is used to automate the project environment setup.

The playbook:

1. Creates the Python virtual environment.
2. Installs the required Scapy dependency.

Inventory:

```ini
[analyzer]
localhost ansible_connection=local
```

The playbook is designed to be **idempotent**, allowing it to be executed repeatedly without unnecessarily recreating an existing environment.

---

## Development Environment

The project was developed and tested using:

| Component            | Environment |
| -------------------- | ----------- |
| Operating System     | Ubuntu      |
| Python               | 3.14.4      |
| Packet Analysis      | Scapy 2.8.0 |
| Network Interface    | `enp0s3`    |
| Virtualization       | VirtualBox  |
| Network Mode         | NAT         |
| Packet Investigation | Wireshark   |
| Traffic Testing      | Nmap        |
| Automation           | Ansible     |

The generated PCAP was temporarily transferred from the Ubuntu guest to the Windows host using a Python HTTP server and VirtualBox NAT port forwarding before being analyzed in Wireshark.

The temporary HTTP server was used only as a file-transfer mechanism and is not part of the analyzer itself.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/Ramuthu20/network-packet-analyzer.git
cd network-packet-analyzer
```

Create the Python virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the analyzer with elevated privileges:

```bash
sudo ./venv/bin/python analyzer.py
```

Press `Ctrl+C` to stop packet capture and generate the report.

---

## Project Structure

```text
network-packet-analyzer/
│
├── analyzer.py
├── analysis_report.txt
├── capture.pcap
├── requirements.txt
├── .gitignore
│
├── ansible/
│   ├── hosts.ini
│   └── setup.yml
│
└── screenshots/
    ├── tcp-analysis.png
    ├── port-scan-analysis.png
    └── dns-analysis.png
```

---

## Technical Skills

### Programming

* Python

### Networking

* Packet Capture
* Network Traffic Analysis
* TCP
* UDP
* ICMP
* ARP
* DNS
* Network Troubleshooting

### Tools

* Scapy
* Wireshark
* Nmap
* Ansible

### Development

* Linux
* Git & GitHub

---

## Project Scope

This project is intentionally implemented as a lightweight, explainable network analysis tool rather than a full enterprise monitoring or intrusion detection platform.

The current implementation focuses on:

**Capture → Analyze → Detect → Investigate → Report**

Future development could include:

* Configurable capture durations
* Additional detection rules
* Historical traffic storage
* Traffic visualization
* Remote network monitoring
