"""
PCAP ANALYSER (COMBINED VERSION)
--------------------------------
This script performs both:
1. General traffic analysis (protocols, IPs, DNS, HTTP)
2. Basic intrusion detection (port scans, SYN floods, plaintext leaks)

Usage:
    python pcap_analyser.py <file.pcap>
"""

import pyshark                     # Library for reading PCAP files using tshark backend
import sys                         # For command-line arguments
from collections import Counter, defaultdict  # Efficient counting & grouping structures


# -------------------------------
# 1. INPUT VALIDATION
# -------------------------------
# Ensure user provides a PCAP file
if len(sys.argv) < 2:
    print("Usage: python pcap_analyser.py <file.pcap>")
    sys.exit(1)

pcap_file = sys.argv[1]
print(f"\n--- FULL ANALYSIS: {pcap_file} ---")


# -------------------------------
# 2. INITIALISE DATA STRUCTURES
# -------------------------------

# General statistics
packet_count = 0                 # Total packets processed
protocols = Counter()            # Count of protocols (e.g., TCP, HTTP)
src_ips = Counter()              # Source IP frequency
dst_ips = Counter()              # Destination IP frequency

# Application-layer insights
dns_queries = []                 # Store DNS queries
http_hosts = []                 # Store HTTP hostnames

# Security / attack detection
port_scans = defaultdict(set)    # Track unique ports contacted per source IP
syn_counts = Counter()           # Count SYN packets per IP (for SYN flood detection)
alerts = []                      # Store detected security issues


# -------------------------------
# 3. LOAD PCAP FILE
# -------------------------------
# keep_packets=False ensures memory efficiency for large files
capture = pyshark.FileCapture(pcap_file, keep_packets=False)

print("Processing packets... (this may take some time)\n")


# -------------------------------
# 4. MAIN ANALYSIS LOOP
# -------------------------------
for packet in capture:
    packet_count += 1

    # ----------------------------------
    # A. PROTOCOL ANALYSIS
    # ----------------------------------
    # highest_layer gives the top protocol (e.g., HTTP, DNS, TCP)
    layer = packet.highest_layer
    protocols[layer] += 1

    # ----------------------------------
    # B. IP ANALYSIS
    # ----------------------------------
    if 'IP' in packet:
        src = packet.ip.src
        dst = packet.ip.dst

        # Count source & destination IPs
        src_ips[src] += 1
        dst_ips[dst] += 1

        # ----------------------------------
        # C. PORT SCAN DETECTION
        # ----------------------------------
        # Track number of unique destination ports per source IP
        if 'TCP' in packet:
            port_scans[src].add(packet.tcp.dstport)

            # Detect SYN packets (possible SYN flood)
            if packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '0':
                syn_counts[src] += 1

        elif 'UDP' in packet:
            port_scans[src].add(packet.udp.dstport)

    # ----------------------------------
    # D. DNS ANALYSIS
    # ----------------------------------
    # Extract queried domain names
    if 'DNS' in packet and hasattr(packet.dns, 'qry_name'):
        dns_queries.append(packet.dns.qry_name)

    # ----------------------------------
    # E. HTTP ANALYSIS
    # ----------------------------------
    # Extract HTTP host headers
    if 'HTTP' in packet and hasattr(packet.http, 'host'):
        http_hosts.append(packet.http.host)

    # ----------------------------------
    # F. PLAINTEXT CREDENTIAL DETECTION
    # ----------------------------------
    # Look for sensitive keywords in unencrypted protocols
    if layer in ['HTTP', 'FTP', 'TELNET']:
        payload = str(packet).lower()

        # Simple keyword-based detection
        if any(word in payload for word in ['password', 'passwd', 'user', 'login', 'authorization']):
            alerts.append(f"[PLAINTEXT] Sensitive data found in {layer} traffic from {src}")


# Close capture after processing
capture.close()


# -------------------------------
# 5. POST-PROCESSING (ATTACK LOGIC)
# -------------------------------

# Detect port scanning (many ports targeted by one IP)
for ip, ports in port_scans.items():
    if len(ports) > 20:
        alerts.append(f"[ATTACK] Port scan detected from {ip} (targeted {len(ports)} ports)")

# Detect SYN flood (too many SYN packets)
for ip, count in syn_counts.items():
    if count > 100:
        alerts.append(f"[ATTACK] SYN flood suspected from {ip} ({count} SYN packets)")


# -------------------------------
# 6. OUTPUT RESULTS
# -------------------------------

# ===== GENERAL SUMMARY =====
print("=" * 60)
print(f"{'GENERAL NETWORK STATISTICS':^60}")
print("=" * 60)

print(f"Total Packets Analysed: {packet_count}")
print(f"Unique Protocols:       {len(protocols)}")


# ---- Protocol Table ----
print("\n" + "-" * 40)
print(f"{'Protocol':<25} | {'Count':<10}")
print("-" * 40)
for proto, count in protocols.most_common(10):
    print(f"{proto:<25} | {count:<10}")


# ---- Top Source IPs ----
print("\n" + "-" * 40)
print(f"{'Top Source IPs':<25} | {'Packets':<10}")
print("-" * 40)
for ip, count in src_ips.most_common(5):
    print(f"{ip:<25} | {count:<10}")


# ---- Top Destination IPs ----
print("\n" + "-" * 40)
print(f"{'Top Destination IPs':<25} | {'Packets':<10}")
print("-" * 40)
for ip, count in dst_ips.most_common(5):
    print(f"{ip:<25} | {count:<10}")


# ---- DNS Queries ----
if dns_queries:
    print("\n" + "-" * 40)
    print("Top DNS Queries")
    print("-" * 40)
    for query, count in Counter(dns_queries).most_common(5):
        print(f"{query} ({count})")


# ---- HTTP Hosts ----
if http_hosts:
    print("\n" + "-" * 40)
    print("HTTP Hosts Found")
    print("-" * 40)
    for host in set(http_hosts):
        print(host)


# ===== SECURITY SECTION =====
print("\n" + "=" * 60)
print(f"{'SECURITY & ATTACK ANALYSIS':^60}")
print("=" * 60)

if not alerts:
    print("No suspicious activity detected.")
else:
    # Remove duplicates for cleaner output
    for alert in set(alerts):
        print(f"!! {alert}")


# ===== END =====
print("\n" + "=" * 60)
print(f"{'ANALYSIS COMPLETE':^60}")
print("=" * 60)