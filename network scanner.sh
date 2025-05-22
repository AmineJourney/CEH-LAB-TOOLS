#!/bin/bash

# ====================================
# Pure Bash Nmap Scanner with Full Recon, UDP, SCTP, SMB, and CVE Extraction (No Python)
# Each scan runs individually and stores results separately
# ====================================

TARGET="$1"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="nmap_scan_${TARGET}_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

if [ -z "$TARGET" ]; then
  echo "Usage: $0 <target IP/domain or range>"
  exit 1
fi

COMMON_OPTS="-n -T3 -v"
COMMON_OPTECHO="-T3 -v"
LIVE_HOSTS_FILE="$OUTPUT_DIR/hosts.txt"
SCAN_COUNTER=0

increment_scan_count() {
  ((SCAN_COUNTER++))
  echo "[+] Completed Scans: $SCAN_COUNTER"
}

# Step 1: Individual Host Discovery Scans
nmap -sn -PE $COMMON_OPTECHO -oN "$OUTPUT_DIR/scan1_icmp_echo.txt" "$TARGET" && increment_scan_count
nmap -sn -PP $COMMON_OPTS -oN "$OUTPUT_DIR/scan1_icmp_timestamp.txt" "$TARGET" && increment_scan_count
nmap -sn -PM $COMMON_OPTS -oN "$OUTPUT_DIR/scan1_icmp_netmask.txt" "$TARGET" && increment_scan_count
nmap -sn -PS22,80,443 $COMMON_OPTS -oN "$OUTPUT_DIR/scan1_tcp_syn.txt" "$TARGET" && increment_scan_count
nmap -sn -PA22,80,443 $COMMON_OPTS -oN "$OUTPUT_DIR/scan1_tcp_ack.txt" "$TARGET" && increment_scan_count
nmap -sn -PO1,6,17 $COMMON_OPTS -oN "$OUTPUT_DIR/scan1_ipproto.txt" "$TARGET" && increment_scan_count
nmap -sn -PR $COMMON_OPTS -oN "$OUTPUT_DIR/scan1_arp.txt" "$TARGET" && increment_scan_count

# Merge clean live IPs into one file
grep -h "Nmap scan report for" "$OUTPUT_DIR"/scan1_*.txt | awk '{print $NF}' | grep -Eo '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | sort -u > "$LIVE_HOSTS_FILE"

# Step 2: Fast Scans (TCP Connect + SYN) Per Host
if [ -s "$LIVE_HOSTS_FILE" ]; then
  while read -r host; do
    nmap -sS -F -Pn $COMMON_OPTS -oN "$OUTPUT_DIR/scan2_syn_$host.txt" "$host" && increment_scan_count
    nmap -sT -F -Pn $COMMON_OPTS -oN "$OUTPUT_DIR/scan2_connect_$host.txt" "$host" && increment_scan_count

    grep -Eo '([0-9]{1,5})/tcp\s+open' "$OUTPUT_DIR/scan2_"*"_$host.txt" | cut -d/ -f1 | sort -u | paste -sd, - - > "$OUTPUT_DIR/open_ports_$host.txt"
  done < "$LIVE_HOSTS_FILE"
else
  echo "[-] No live hosts discovered."
  exit 1
fi

# Step 3: Full Detailed Scans Using Extracted Ports
while read -r host; do
  PORTS=$(cat "$OUTPUT_DIR/open_ports_$host.txt")
  [ -z "$PORTS" ] && continue

  nmap -sS -Pn $COMMON_OPTS -p "$PORTS" -oN "$OUTPUT_DIR/scan3_syn_$host.txt" "$host" && increment_scan_count
  nmap -sU -Pn $COMMON_OPTS -p "$PORTS" -oN "$OUTPUT_DIR/scan3_udp_$host.txt" "$host" && increment_scan_count
  nmap -sY -Pn $COMMON_OPTS -p "$PORTS" -oN "$OUTPUT_DIR/scan3_sctp_$host.txt" "$host" && increment_scan_count
  nmap -sV -Pn $COMMON_OPTS -p "$PORTS" -oN "$OUTPUT_DIR/scan3_version_$host.txt" "$host" && increment_scan_count
  nmap -sC -Pn $COMMON_OPTS -p "$PORTS" -oN "$OUTPUT_DIR/scan3_script_basic_$host.txt" "$host" && increment_scan_count
  nmap -A  -Pn $COMMON_OPTS -p "$PORTS" -oN "$OUTPUT_DIR/scan3_aggressive_$host.txt" "$host" && increment_scan_count
  nmap -O  -Pn $COMMON_OPTS         -oN "$OUTPUT_DIR/scan3_osdetect_$host.txt" "$host" && increment_scan_count

  for script in vulners dns-brute dns-service-discovery smb-os-discovery smb-enum-shares smb-enum-users; do
    nmap --script "$script" -Pn $COMMON_OPTS -p "$PORTS" -oN "$OUTPUT_DIR/scan3_nse_${script}_$host.txt" "$host" && increment_scan_count
  done

  nmap --traceroute -Pn $COMMON_OPTS -p "$PORTS" -oN "$OUTPUT_DIR/scan3_trace_$host.txt" "$host" && increment_scan_count
done < "$LIVE_HOSTS_FILE"

# Step 4: Extract CVEs from NSE results (if available)
VULN_XML="$OUTPUT_DIR/cve_hosts.xml"
echo "<vulnerabilities>" > "$VULN_XML"
if command -v xmlstarlet > /dev/null; then
  for nse_txt in "$OUTPUT_DIR"/scan3_nse_vulners_*.txt; do
    host=$(echo "$nse_txt" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
    if grep -q "CVE" "$nse_txt"; then
      echo "  <host ip=\"$host\">" >> "$VULN_XML"
      grep -oE "CVE-[0-9]{4}-[0-9]{4,}" "$nse_txt" | sort -u | while read -r cve; do
        echo "    <cve>$cve</cve>" >> "$VULN_XML"
      done
      echo "  </host>" >> "$VULN_XML"
    fi
  done
fi
echo "</vulnerabilities>" >> "$VULN_XML"

# Final Summary
echo -e "\n=============================="
echo "Scan complete. Results saved in: $OUTPUT_DIR"
echo "Live hosts: $LIVE_HOSTS_FILE"
echo "Open ports per host in: open_ports_<host>.txt"
echo "All scan outputs: scan*_*.txt"
echo "CVE summary (XML): $VULN_XML"
echo "Total scans executed: $SCAN_COUNTER"
echo "=============================="
