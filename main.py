import json
import os
import time
from scapy.all import sniff, get_if_list, get_if_addr
from colorama import Fore, Style
import csv


seen_ips = []


if not os.path.exists('logs'):
    os.makedirs('logs')


log_file_path = 'logs/network_logs.csv'

if not os.path.exists(log_file_path):
    with open(log_file_path, 'w', newline='') as log_file:
        log_writer = csv.writer(log_file)
        log_writer.writerow(['Timestamp', 'Severity', 'Alert', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port'])

# load the IDS rules from JSON file
def load_rules():
    try:
        with open('rules/rules.json', 'r') as file:
            return json.load(file)['rules']
    except FileNotFoundError:
        print(Fore.RED + "Error: rules.json not found!" + Style.RESET_ALL)
        return []
    except json.JSONDecodeError:
        print(Fore.RED + "Error: Invalid JSON format in rules.json!" + Style.RESET_ALL)
        return []

# Detect suspicious activity by packet parsing
def detect_intrusion(pkt_summary, rules):
    alerts = []
    parts = pkt_summary.split()
    src_ip, dst_ip, src_port, dst_port = None, None, None, None

    print(f"Parts: {parts}")  # Debug: See the split summary

    # Extract IPs and ports
    for i, part in enumerate(parts):
        if ">" in part and i > 0 and i + 1 < len(parts):
            src = parts[i - 1].split(':')
            dst = parts[i + 1].split(':')
            src_ip = src[0]
            src_port = src[1] if len(src) > 1 else None
            dst_ip = dst[0]
            dst_port = dst[1] if len(dst) > 1 else None
            if dst_port == "https":
                dst_port = "443"
            elif dst_port == "http":
                dst_port = "80"
            elif dst_port == "dns":
                dst_port = "53"
            break

    print(f"Extracted - src_ip: {src_ip}, dst_ip: {dst_ip}, src_port: {src_port}, dst_port: {dst_port}")  # Debug

    # Use rules
    for rule in rules:
        try:
            condition = rule["condition"]
            if "IP in pkt and pkt[IP].src" in condition:
                rule_ip = condition.split("'")[1]
                if src_ip == rule_ip:
                    alerts.append(rule["description"])
            elif "TCP in pkt and pkt[TCP].dport" in condition:
                port = int(condition.split("==")[1].strip())
                if dst_port and int(dst_port) == port:
                    alerts.append(rule["description"])
            elif condition == "IP in pkt":
                if src_ip:
                    alerts.append(rule["description"])
        except Exception as e:
            print(Fore.YELLOW + f"Error evaluating rule: {rule['condition']} | {str(e)}" + Style.RESET_ALL)

    return alerts, src_ip, dst_ip, src_port, dst_port

# Packet handler
def packet_handler(pkt):
    pkt_summary = pkt.summary()
    print(f"Raw packet: {pkt_summary}")

    alerts, src_ip, dst_ip, src_port, dst_port = detect_intrusion(pkt_summary, load_rules())

    if src_ip and dst_ip:  # If we successfully extracted IPs
        print(Fore.GREEN + f"IP Packet: {src_ip} -> {dst_ip}" + Style.RESET_ALL)
        if src_port and dst_port:
            print(f"Ports: {src_port} -> {dst_port}")
        if src_ip not in seen_ips:
            seen_ips.append(src_ip)
        if alerts:
            for alert in alerts:
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                severity = "ALERT"
                log_entry = [timestamp, severity, alert, src_ip, dst_ip, src_port, dst_port]
                print(Fore.RED + f"ALERT: {alert} | Source IP: {src_ip} -> Destination IP: {dst_ip}" + Style.RESET_ALL)

                # Write to log file (CSV)
                with open(log_file_path, 'a', newline='') as log_file:
                    log_writer = csv.writer(log_file)
                    log_writer.writerow(log_entry)

    else:
        print(Fore.YELLOW + "Non-IP packet:" + Style.RESET_ALL, pkt_summary)

# Start sniffing
def start_sniffing():
    print(Fore.GREEN + "Starting Intrusion Detection System..." + Style.RESET_ALL)
    try:
        interfaces = get_if_list()
        print("Available interfaces:", interfaces)
        for iface in interfaces:
            if iface == "\\Device\\NPF_Loopback":
                continue
            try:
                ip = get_if_addr(iface)
                if ip and ip != "0.0.0.0":
                    print(f"Using interface: {iface} with IP: {ip}")
                    sniff(iface=iface, prn=packet_handler, count=10, timeout=10)
                    break
            except Exception as e:
                print(Fore.YELLOW + f"Skipping {iface}: {str(e)}" + Style.RESET_ALL)
        else:
            print(Fore.RED + "No active interface found!" + Style.RESET_ALL)
    except PermissionError:
        print(Fore.RED + "Error: Permission denied. Run as Administrator." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Error during sniffing: {str(e)}" + Style.RESET_ALL)

if __name__ == "__main__":
    start_sniffing()  # Start the sniffing process
