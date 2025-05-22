#!/bin/bash

# ====================================
# Adaptive Nmap Scanner with Full Recon, JSON Outputs, UDP, SCTP, and CVE Matching
# ====================================

TARGET="$1"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="nmap_scan_$TARGET_$TIMESTAMP"
mkdir -p "$OUTPUT_DIR"

if [ -z "$TARGET" ]; then
  echo "Usage: $0 <target IP/domain or range>"
  exit 1
fi

COMMON_OPTS="-n -T3 -v"
LIVE_HOSTS_FILE="$OUTPUT_DIR/live_hosts.txt"
OPEN_PORTS_FILE="$OUTPUT_DIR/open_ports.txt"

# Step 1: Host Discovery (ICMP, ARP, IP Proto)
echo "[+] Performing host discovery..."
nmap -sn --script=icmp-echo,icmp-timestamp,icmp-address-mask $COMMON_OPTS -oX "$OUTPUT_DIR/ping_scan.xml" "$TARGET"
nmap -sn -PR $COMMON_OPTS -oX "$OUTPUT_DIR/arp_scan.xml" "$TARGET"
nmap -sO -Pn $COMMON_OPTS -oX "$OUTPUT_DIR/ipproto_scan.xml" "$TARGET"

# Merge live hosts from all scans
python3 - <<EOF
import xml.etree.ElementTree as ET
import os
hosts = set()
for file in ["ping_scan.xml", "arp_scan.xml", "ipproto_scan.xml"]:
    path = os.path.join("$OUTPUT_DIR", file)
    if os.path.exists(path):
        root = ET.parse(path).getroot()
        for host in root.findall("host"):
            if host.find("status").get("state") == "up":
                ip = host.find("address").get("addr")
                hosts.add(ip)
with open("$LIVE_HOSTS_FILE", "w") as f:
    f.write("\n".join(sorted(hosts)))
EOF

# Step 2: Fast Port Scan (TCP)
echo "[+] Scanning live hosts for open TCP ports..."
nmap -sS -F -Pn $COMMON_OPTS -iL "$LIVE_HOSTS_FILE" -oX "$OUTPUT_DIR/fast_tcp_scan.xml"

# Extract open TCP ports
python3 - <<EOF
import xml.etree.ElementTree as ET
root = ET.parse("$OUTPUT_DIR/fast_tcp_scan.xml").getroot()
ports = set()
for host in root.findall("host"):
    for port in host.findall("ports/port"):
        if port.find("state").get("state") == "open":
            ports.add(port.get("portid"))
with open("$OPEN_PORTS_FILE", "w") as f:
    f.write(",".join(sorted(ports)))
EOF

OPEN_PORTS=$(cat "$OPEN_PORTS_FILE")

# Step 3: Full TCP/UDP/SCTP Scan + DNS + OS + CVEs
if [ -n "$OPEN_PORTS" ]; then
  echo "[+] Running detailed scans (TCP/UDP/SCTP), OS, DNS, traceroute, and CVEs..."
  nmap -sS -sU -sY -sV -sC -A -O --script vulners,dns-brute,dns-service-discovery,traceroute --traceroute \
       -Pn $COMMON_OPTS -p "$OPEN_PORTS" -iL "$LIVE_HOSTS_FILE" -oX "$OUTPUT_DIR/full_scan.xml"
else
  echo "[-] No open TCP ports found. Skipping detailed scan."
fi

# Step 4: JSON Conversion for each scan
for xml in ping_scan.xml arp_scan.xml ipproto_scan.xml fast_tcp_scan.xml full_scan.xml; do
  if [ -f "$OUTPUT_DIR/$xml" ]; then
    echo "[+] Converting $xml to JSON..."
    python3 -c "
import xmltodict, json
with open('$OUTPUT_DIR/$xml') as f:
    j = xmltodict.parse(f.read())
with open('$OUTPUT_DIR/${xml%.xml}.json', 'w') as out:
    json.dump(j, out, indent=2)
" || echo "[!] Failed to convert $xml"
  fi
done

# Step 5: Extract CVE Summary JSON
SUMMARY_FILE="$OUTPUT_DIR/summary.json"
python3 - <<EOF
import xml.etree.ElementTree as ET
import json
import os

xml_path = "$OUTPUT_DIR/full_scan.xml"
if not os.path.exists(xml_path):
    print("No full scan results to summarize.")
    exit(0)

tree = ET.parse(xml_path)
root = tree.getroot()
summaries = []

for host in root.findall("host"):
    address = host.find("address").get("addr")
    ports = host.find("ports")
    if ports is None:
        continue
    for port in ports.findall("port"):
        portid = port.get("portid")
        protocol = port.get("protocol")
        service_elem = port.find("service")
        cpe = service_elem.get("cpe") if service_elem is not None else None
        name = service_elem.get("name") if service_elem is not None else None
        product = service_elem.get("product") if service_elem is not None else None
        version = service_elem.get("version") if service_elem is not None else None

        cves = []
        for script in port.findall("script"):
            if script.get("id") == "vulners":
                output = script.get("output")
                for line in output.split("\n"):
                    if "CVE-" in line:
                        cves.append(line.strip())

        summaries.append({
            "host": address,
            "port": portid,
            "protocol": protocol,
            "service": name,
            "product": product,
            "version": version,
            "cpe": cpe,
            "cves": cves
        })

with open("$SUMMARY_FILE", "w") as f:
    json.dump(summaries, f, indent=2)
EOF

# Final message
echo -e "\n=============================="
echo "Scan complete. Results saved in: $OUTPUT_DIR"
echo "Key findings summarized in: $SUMMARY_FILE"
echo "=============================="
