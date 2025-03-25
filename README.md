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
```

### Setup Instructions
### 1. Clone the Repository
If you're setting up the project from a GitHub repository, clone it to your local machine (skip this if you're adding the project manually).

bash
Copy code
git clone https://github.com/yourusername/repository-name.git
If you're manually adding files, ensure you have the entire project folder on your local machine.

### 2. Directory Structure:

The project directory structure is as follows:

```bash
network-intrusion-detection/
│
├── logs/
│   └── network_logs.txt      # Logs file that stores intrusion alerts
│
├── rules/
│   └── rules.json            # JSON file containing IDS rules
│
├── nids.py                   # Main Python script for IDS
├── README.md                 # This file
└── requirements.txt          # List of required Python libraries
```

### 3. Install Required Python Packages
This project requires Python 3 and some external libraries. You can install them using pip.

**Scapy**: For sniffing and analyzing network packets.

**Colorama**: For colored terminal output.

You can install the required dependencies by running the following command in your terminal (make sure you're in the project folder):


pip install -r requirements.txt

**If you don't have a requirements.txt file**,

you can manually install the dependencies with:

pip install scapy colorama

### 4. Add Rules File
The program uses a rules.json file to define the conditions for detecting suspicious activity. You can either create the file manually or use the sample provided.

Here's an example structure for the rules.json file:

json
```bash
{
    "rules": [
        {"condition": "IP in pkt", "description": "Any IP packet detected"},
        {"condition": "TCP in pkt and pkt[TCP].dport == 443", "description": "HTTPS traffic detected"},
        {"condition": "IP in pkt and pkt[IP].src == '10.0.0.16'", "description": "Traffic from this machine"}
    ]
}
```
Save this file as rules.json in a rules/ directory inside your project folder.

### 5. Run the Program
Now that everything is set up, you can run the program.

In your terminal, navigate to the project directory and run:

python intrusion_detection.py
This will start the program and begin sniffing network traffic for suspicious activity.

### 6. View Logs
The program writes alerts to a log file called network_logs.txt. You can open this file in a text editor to review the detected suspicious activity.

The logs will be stored in the logs/ directory of the project.



