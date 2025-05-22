#!/bin/bash

# ====================================
# Pure Bash Nmap Scanner with Full Recon, UDP, SCTP, and CVE Extraction (No Python)
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
nmap -sn -PE -PP -PM $COMMON_OPTS -oX "$OUTPUT_DIR/ping_scan.xml" "$TARGET"
nmap -sn -PR $COMMON_OPTS -oX "$OUTPUT_DIR/arp_scan.xml" "$TARGET"
nmap -sn -PO $COMMON_OPTS -oX "$OUTPUT_DIR/ipproto_scan.xml" "$TARGET"
nmap -sO -Pn $COMMON_OPTS -oX "$OUTPUT_DIR/ipproto_scan.xml" "$TARGET"

# Merge live hosts from all scans
echo "[+] Extracting live hosts..."
grep -h 'addrtype="ipv4"' "$OUTPUT_DIR"/*.xml | \
  sed -n 's/.*addr="\([0-9.]*\)".*addrtype="ipv4".*/\1/p' | sort -u > "$LIVE_HOSTS_FILE"

# Step 2: Fast Port Scan (TCP)
echo "[+] Scanning live hosts for open TCP ports..."
nmap -sS -F -Pn $COMMON_OPTS -iL "$LIVE_HOSTS_FILE" -oX "$OUTPUT_DIR/fast_tcp_scan.xml"

# Extract open TCP ports
echo "[+] Extracting open ports..."
grep 'portid' "$OUTPUT_DIR/fast_tcp_scan.xml" | grep open | \
  sed -n 's/.*portid="\([0-9]*\)".*/\1/p' | sort -u | paste -sd, - > "$OPEN_PORTS_FILE"

OPEN_PORTS=$(cat "$OPEN_PORTS_FILE")

# Step 3: Full TCP/UDP/SCTP Scan + DNS + OS + CVEs
if [ -n "$OPEN_PORTS" ]; then
  echo "[+] Running detailed scans (TCP/UDP/SCTP), OS, DNS, traceroute, and CVEs..."
  nmap -sS -sU -sY -sV -sC -A -O \
       --script vulners,dns-brute,dns-service-discovery --traceroute \
       -Pn $COMMON_OPTS -p "$OPEN_PORTS" -iL "$LIVE_HOSTS_FILE" -oX "$OUTPUT_DIR/full_scan.xml"
else
  echo "[-] No open TCP ports found. Skipping detailed scan."
fi

# Step 4: Extract CVE Summary (text format)
SUMMARY_FILE="$OUTPUT_DIR/cve_summary.txt"
echo "[+] Extracting CVEs from full scan..."
grep -A 5 'script id="vulners"' "$OUTPUT_DIR/full_scan.xml" | grep 'CVE-' | sed -n 's/.*\(CVE-[0-9\-]*\).*/\1/p' | sort -u > "$SUMMARY_FILE"

# Final message
echo -e "\n=============================="
echo "Scan complete. Results saved in: $OUTPUT_DIR"
echo "Key CVEs listed in: $SUMMARY_FILE"
echo "=============================="
