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

VERBOSE=0  # Set to 1 to enable verbose logging

log_verbose() {
  if [ "$VERBOSE" -eq 1 ]; then
    echo "$1"
  fi
}

COMMON_OPTS="-n -T3 -v"
COMMON_OPTECHO="-T3 -v"
LIVE_HOSTS_FILE="$OUTPUT_DIR/hosts.txt"
SCAN_COUNTER=0
SCAN_TRACKER_FILE="$OUTPUT_DIR/scan_status.txt"
touch "$SCAN_TRACKER_FILE"

track_scan_status() {
  local scan_name="$1"
  local status="$2"
  echo "$scan_name: $status" >> "$SCAN_TRACKER_FILE"
}

increment_scan_count() {
  ((SCAN_COUNTER++))
  log_verbose "[+] Completed Scans: $SCAN_COUNTER"
}

# Step 1: Individual Host Discovery Scans
nmap -sn -PE $COMMON_OPTECHO -oN "$OUTPUT_DIR/scan1_icmp_echo.txt" "$TARGET" && {
  increment_scan_count
  track_scan_status "scan1_icmp_echo" "done"
} || track_scan_status "scan1_icmp_echo" "errored"

nmap -sn -PP $COMMON_OPTS -oN "$OUTPUT_DIR/scan1_icmp_timestamp.txt" "$TARGET" && {
  increment_scan_count
  track_scan_status "scan1_icmp_timestamp" "done"
} || track_scan_status "scan1_icmp_timestamp" "errored"

nmap -sn -PM $COMMON_OPTS -oN "$OUTPUT_DIR/scan1_icmp_netmask.txt" "$TARGET" && {
  increment_scan_count
  track_scan_status "scan1_icmp_netmask" "done"
} || track_scan_status "scan1_icmp_netmask" "errored"

nmap -sn -PS22,80,443 $COMMON_OPTS -oN "$OUTPUT_DIR/scan1_tcp_syn.txt" "$TARGET" && {
  increment_scan_count
  track_scan_status "scan1_tcp_syn" "done"
} || track_scan_status "scan1_tcp_syn" "errored"

nmap -sn -PA22,80,443 $COMMON_OPTS -oN "$OUTPUT_DIR/scan1_tcp_ack.txt" "$TARGET" && {
  increment_scan_count
  track_scan_status "scan1_tcp_ack" "done"
} || track_scan_status "scan1_tcp_ack" "errored"

nmap -sn -PO1,6,17 $COMMON_OPTS -oN "$OUTPUT_DIR/scan1_ipproto.txt" "$TARGET" && {
  increment_scan_count
  track_scan_status "scan1_ipproto" "done"
} || track_scan_status "scan1_ipproto" "errored"

nmap -sn -PR $COMMON_OPTS -oN "$OUTPUT_DIR/scan1_arp.txt" "$TARGET" && {
  increment_scan_count
  track_scan_status "scan1_arp" "done"
} || track_scan_status "scan1_arp" "errored"

# Merge clean live IPs into one file
grep -h "Nmap scan report for" "$OUTPUT_DIR"/scan1_*.txt | awk '{print $NF}' | grep -Eo '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | sort -u > "$LIVE_HOSTS_FILE"

# Step 2: Fast Scans (TCP Connect + SYN) Per Host
if [ -s "$LIVE_HOSTS_FILE" ]; then
  while read -r host; do
    nmap -sS -F -Pn $COMMON_OPTS -oN "$OUTPUT_DIR/scan2_syn_$host.txt" "$host" && {
      increment_scan_count
      track_scan_status "scan2_syn_$host" "done"
    } || track_scan_status "scan2_syn_$host" "errored"

    nmap -sT -F -Pn $COMMON_OPTS -oN "$OUTPUT_DIR/scan2_connect_$host.txt" "$host" && {
      increment_scan_count
      track_scan_status "scan2_connect_$host" "done"
    } || track_scan_status "scan2_connect_$host" "errored"

    TCP_PORTS=$(grep -Eh '^[0-9]+/tcp\s+open' "$OUTPUT_DIR/scan2_syn_$host.txt" "$OUTPUT_DIR/scan2_connect_$host.txt" | cut -d/ -f1 | sort -nu | paste -sd, -)
    if [ -n "$TCP_PORTS" ]; then
      echo "$TCP_PORTS" > "$OUTPUT_DIR/open_ports_tcp_$host.txt"
      log_verbose "[+] TCP ports found for $host: $TCP_PORTS"
    else
      log_verbose "[-] No TCP ports found for $host. Skipping port file creation."
      rm -f "$OUTPUT_DIR/open_ports_tcp_$host.txt"
    fi

    UDP_PORTS=""
    # Add UDP port extraction logic here later if needed
  done < "$LIVE_HOSTS_FILE"
else
  echo "[-] No live hosts discovered."
  exit 1
fi

# Step 3: Full Detailed Scans Using Extracted Ports
while read -r host; do
  TCP_PORTS_FILE="$OUTPUT_DIR/open_ports_tcp_$host.txt"
  UDP_PORTS_FILE="$OUTPUT_DIR/open_ports_udp_$host.txt"

  [ -f "$TCP_PORTS_FILE" ] && TCP_PORTS=$(tr -d ' \n\r' < "$TCP_PORTS_FILE") || TCP_PORTS=""
  [ -f "$UDP_PORTS_FILE" ] && UDP_PORTS=$(tr -d ' \n\r' < "$UDP_PORTS_FILE") || UDP_PORTS=""

  if [ -z "$TCP_PORTS" ]; then
    track_scan_status "scan3_tcp_$host" "skipped"
  else
    nmap -sS -Pn $COMMON_OPTS -p "$TCP_PORTS" -oN "$OUTPUT_DIR/scan3_syn_$host.txt" "$host" && {
      increment_scan_count
      track_scan_status "scan3_syn_$host" "done"
    } || track_scan_status "scan3_syn_$host" "errored"

    nmap -sY -Pn $COMMON_OPTS -p "$TCP_PORTS" -oN "$OUTPUT_DIR/scan3_sctp_$host.txt" "$host" && {
      increment_scan_count
      track_scan_status "scan3_sctp_$host" "done"
    } || track_scan_status "scan3_sctp_$host" "errored"

    nmap -sV -Pn $COMMON_OPTS -p "$TCP_PORTS" -oN "$OUTPUT_DIR/scan3_version_$host.txt" "$host" && {
      increment_scan_count
      track_scan_status "scan3_version_$host" "done"
    } || track_scan_status "scan3_version_$host" "errored"

    nmap -sC -Pn $COMMON_OPTS -p "$TCP_PORTS" -oN "$OUTPUT_DIR/scan3_script_basic_$host.txt" "$host" && {
      increment_scan_count
      track_scan_status "scan3_script_basic_$host" "done"
    } || track_scan_status "scan3_script_basic_$host" "errored"

    nmap -A -Pn $COMMON_OPTS -p "$TCP_PORTS" -oN "$OUTPUT_DIR/scan3_aggressive_$host.txt" "$host" && {
      increment_scan_count
      track_scan_status "scan3_aggressive_$host" "done"
    } || track_scan_status "scan3_aggressive_$host" "errored"
  fi

  if [ -z "$UDP_PORTS" ]; then
    track_scan_status "scan3_udp_$host" "skipped"
  else
    nmap -sU -Pn $COMMON_OPTS -p "$UDP_PORTS" -oN "$OUTPUT_DIR/scan3_udp_$host.txt" "$host" && {
      increment_scan_count
      track_scan_status "scan3_udp_$host" "done"
    } || track_scan_status "scan3_udp_$host" "errored"
  fi

  nmap -O -Pn $COMMON_OPTS -oN "$OUTPUT_DIR/scan3_osdetect_$host.txt" "$host" && {
    increment_scan_count
    track_scan_status "scan3_osdetect_$host" "done"
  } || track_scan_status "scan3_osdetect_$host" "errored"

  for script in vulners dns-brute dns-service-discovery smb-os-discovery smb-enum-shares smb-enum-users; do
    if [ -n "$TCP_PORTS" ]; then
      nmap --script "$script" -Pn $COMMON_OPTS -p "$TCP_PORTS" -oN "$OUTPUT_DIR/scan3_nse_${script}_$host.txt" "$host" && {
        increment_scan_count
        track_scan_status "scan3_nse_${script}_$host" "done"
      } || track_scan_status "scan3_nse_${script}_$host" "errored"
    else
      track_scan_status "scan3_nse_${script}_$host" "skipped"
    fi
  done

  if [ -n "$TCP_PORTS" ]; then
    nmap --traceroute -Pn $COMMON_OPTS -p "$TCP_PORTS" -oN "$OUTPUT_DIR/scan3_trace_$host.txt" "$host" && {
      increment_scan_count
      track_scan_status "scan3_trace_$host" "done"
    } || track_scan_status "scan3_trace_$host" "errored"
  else
    track_scan_status "scan3_trace_$host" "skipped"
  fi

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
log_verbose "\n=============================="
echo "Scan complete. Results saved in: $OUTPUT_DIR"
echo "Live hosts: $LIVE_HOSTS_FILE"
echo "Open ports per host in: open_ports_<host>.txt"
echo "All scan outputs: scan*_*.txt"
echo "Scan status tracker: $SCAN_TRACKER_FILE"
echo "CVE summary (XML): $VULN_XML"
echo "Total scans executed: $SCAN_COUNTER"
echo -e "\n========= Scan Status Summary ========="
grep -E 'done|errored|skipped' "$SCAN_TRACKER_FILE" | sort
log_verbose "=============================="
