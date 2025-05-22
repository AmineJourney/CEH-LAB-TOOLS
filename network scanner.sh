#!/bin/bash

# ==============================
# Full Nmap Multi-Technique Scanner
# Plus JSON summary with versions and CVE matching
# ==============================

TARGET="$1"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="nmap_scan_$TARGET_$TIMESTAMP"
mkdir -p "$OUTPUT_DIR"

if [ -z "$TARGET" ]; then
  echo "Usage: $0 <target IP/domain>"
  exit 1
fi

# Shared options
COMMON_OPTS="-n -T3 -v"

# Step 0: ICMP-based Ping Scan (Echo, Timestamp, Address-mask)
nmap -sn --script=icmp-echo,icmp-timestamp,icmp-address-mask $COMMON_OPTS -oA "$OUTPUT_DIR/icmp_ping" "$TARGET"

# Step 0.1: ARP Scan (only for local network targets)
nmap -sn -PR -oA "$OUTPUT_DIR/arp_scan" "$TARGET"

# Step 0.2: IP Protocol Ping Scan
nmap -sO -Pn $COMMON_OPTS -oA "$OUTPUT_DIR/ip_proto_ping" "$TARGET"

# Step 1: TCP Connect / Full Open
nmap -sT -Pn $COMMON_OPTS -oA "$OUTPUT_DIR/tcp_connect" "$TARGET"

# Step 2: Stealth (Half-Open) Scan
nmap -sS -Pn $COMMON_OPTS -oA "$OUTPUT_DIR/stealth_halfopen" "$TARGET"

# Step 3: UDP Scan
nmap -sU -Pn $COMMON_OPTS -oA "$OUTPUT_DIR/udp" "$TARGET"

# Step 4: SCTP INIT Scan
nmap -sY -Pn $COMMON_OPTS -oA "$OUTPUT_DIR/sctp_init" "$TARGET"

# Step 5: SCTP COOKIE-ECHO Scan
nmap -sZ -Pn $COMMON_OPTS -oA "$OUTPUT_DIR/sctp_cookie" "$TARGET"

# Step 6: Xmas Scan
nmap -sX -Pn $COMMON_OPTS -oA "$OUTPUT_DIR/xmas" "$TARGET"

# Step 7: FIN Scan
nmap -sF -Pn $COMMON_OPTS -oA "$OUTPUT_DIR/fin" "$TARGET"

# Step 8: NULL Scan
nmap -sN -Pn $COMMON_OPTS -oA "$OUTPUT_DIR/null" "$TARGET"

# Step 9: Maimon Scan
nmap -sM -Pn $COMMON_OPTS -oA "$OUTPUT_DIR/maimon" "$TARGET"

# Step 10: Inverse TCP Flag Scans
nmap -sF -sN -sX -Pn $COMMON_OPTS -oA "$OUTPUT_DIR/inverse_flags" "$TARGET"

# Step 11: ACK Flag Probe
nmap -sA -Pn $COMMON_OPTS -oA "$OUTPUT_DIR/ack_probe" "$TARGET"

# Step 12: TTL-based Scan
nmap -sA --ttl 100 -Pn $COMMON_OPTS -oA "$OUTPUT_DIR/ttl_scan" "$TARGET"

# Step 13: Window Scan
nmap -sA -sW -Pn $COMMON_OPTS -oA "$OUTPUT_DIR/window_scan" "$TARGET"

# Step 14: Version Detection + CVE Extraction
nmap -sV --script vulners -Pn $COMMON_OPTS -oX "$OUTPUT_DIR/version_cves.xml" "$TARGET"

# Optional: IDLE/IPID Scan (requires zombie IP)
# ZOMBIE="<zombie_ip>"
# nmap -Pn -p- -sI "$ZOMBIE" $COMMON_OPTS -oA "$OUTPUT_DIR/idle_ipid" "$TARGET"

# Step 15: Generate JSON Summary
SUMMARY_FILE="$OUTPUT_DIR/summary.json"
python3 - <<EOF
import xml.etree.ElementTree as ET
import json

xml_path = "$OUTPUT_DIR/version_cves.xml"
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
