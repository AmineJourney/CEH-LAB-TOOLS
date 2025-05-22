#!/bin/bash

# ====================================
# Pure Bash Nmap Scanner with Full Recon, UDP, SCTP, SMB, and CVE Extraction (No Python)
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
LIVE_HOSTS_FILE="$OUTPUT_DIR/hosts.txt"
OPEN_PORTS_FILE="$OUTPUT_DIR/open_ports.txt"

# Step 1: Host Discovery (ICMP, ARP, IP Proto, TCP/UDP/Other)
echo "[+] Performing host discovery (ICMP, TCP, ARP, IP Protocol)..."
nmap -sn -PE -PP -PM -PS22,80,443 -PA22,80,443 -PO1,6,17 $COMMON_OPTS -oN "$OUTPUT_DIR/scan1.txt" "$TARGET"
nmap -sn -PR $COMMON_OPTS -oN "$OUTPUT_DIR/scan1_arp.txt" "$TARGET"
nmap -sO -Pn $COMMON_OPTS -oN "$OUTPUT_DIR/scan1_ipproto.txt" "$TARGET"

# Merge live hosts from all scans
echo "[+] Extracting live hosts..."
grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "$OUTPUT_DIR/scan1.txt" "$OUTPUT_DIR/scan1_arp.txt" "$OUTPUT_DIR/scan1_ipproto.txt" | sort -u > "$LIVE_HOSTS_FILE"

# Step 2: Fast Port Scan (TCP)
echo "[+] Scanning live hosts for open TCP ports..."
nmap -sS -F -Pn $COMMON_OPTS -iL "$LIVE_HOSTS_FILE" -oN "$OUTPUT_DIR/scan2.txt"

# Extract open TCP ports
echo "[+] Extracting open ports..."
grep -Eo '([0-9]{1,5})/tcp\s+open' "$OUTPUT_DIR/scan2.txt" | cut -d/ -f1 | sort -u | paste -sd, - > "$OPEN_PORTS_FILE"

OPEN_PORTS=$(cat "$OPEN_PORTS_FILE")

# Step 3: Full TCP/UDP/SCTP Scan + DNS + OS + SMB + CVEs
if [ -n "$OPEN_PORTS" ]; then
  echo "[+] Running detailed scans (TCP/UDP/SCTP), OS, DNS, SMB, traceroute, and CVEs..."
  nmap -sS -sU -sY -sV -sC -A -O \
       --script vulners,dns-brute,dns-service-discovery,smb-os-discovery,smb-enum-shares,smb-enum-users \
       --traceroute \
       -Pn $COMMON_OPTS -p "$OPEN_PORTS" -iL "$LIVE_HOSTS_FILE" \
       -oX "$OUTPUT_DIR/full_scan.xml" -oN "$OUTPUT_DIR/full_scan.txt"
else
  echo "[-] No open TCP ports found. Skipping detailed scan."
fi

# Step 4: Extract CVE Summary with host and port context
VULN_XML="$OUTPUT_DIR/cve_hosts.xml"
echo "[+] Extracting CVEs from full scan..."

if command -v xmlstarlet > /dev/null; then
  xmlstarlet sel -t \
    -m "//host[ports/port/script[@id='vulners']]" \
    -o "<host>" \
    -e address -a addr -v "@addr" -a addrtype -v "@addrtype" -n -b \
    -m "ports/port[script[@id='vulners']]" \
      -o "<port>" \
      -e portid -v "@portid" -b \
      -e protocol -v "@protocol" -b \
      -e service -v "concat(service/@name, ' ', service/@product, ' ', service/@version)" -b \
      -m "script[@id='vulners']/table[@key='cve']/table" \
        -o "<cve>" -v "key[1]" -o "</cve>" \
      -b -o "</port>" \
    -b -o "</host>" \
    "$OUTPUT_DIR/full_scan.xml" > "$VULN_XML"
else
  echo "[!] xmlstarlet is not installed. Cannot extract CVE XML summary."
fi

# Final message
echo -e "\n=============================="
echo "Scan complete. Results saved in: $OUTPUT_DIR"
echo "Live hosts: $LIVE_HOSTS_FILE"
echo "Fast TCP ports: $OPEN_PORTS_FILE"
echo "Full Scan: $OUTPUT_DIR/full_scan.txt + $OUTPUT_DIR/full_scan.xml"
echo "ARP Scan: $OUTPUT_DIR/scan1_arp.txt"
echo "IP Protocol Scan: $OUTPUT_DIR/scan1_ipproto.txt"
echo "CVE Summary (XML): $VULN_XML"
echo "=============================="
