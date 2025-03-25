# Network Intrusion Detection System (NIDS)

This project implements a simple **Intrusion Detection System (IDS)** using **Python** and **Scapy** to sniff network traffic and identify suspicious activity based on predefined rules. The system can analyze traffic, detect common intrusion patterns, and log alerts.

# Features
Packet Sniffing: Monitors network traffic in real-time using Scapy.
- **Suspicious Activity Detection**: Uses predefined rules to identify potential intrusions.
- **Alert Logging**: Logs intrusion alerts in CSV format with timestamps, severity levels, and detailed information.
- **Simple Rule-based Detection**: Alerts triggered by matching conditions like specific IP addresses or port numbers.


## Requirements

### 1. **Python 3.x**:
Make sure you have **Python 3.x** installed. If you don’t have Python installed, you can download and install it from [python.org](https://www.python.org/downloads/).

### 2. **Required Libraries**:
You’ll need the following Python libraries:
- `scapy`: Used for packet sniffing and parsing.
- `colorama`: Used for colorizing terminal output.

Install the required libraries by running the following command in your terminal:

```bash
pip install scapy colorama




