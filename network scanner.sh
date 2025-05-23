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
  echo -e "Usage: $0 <target IP/domain or range>"
  exit 1
fi

VERBOSE=0  # Set to 1 to enable verbose logging

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
  echo -e "${YELLOW}[INFO]${NC} $1"
}

log_success() {
  echo -e "${GREEN}[+]${NC} $1"
}

log_error() {
  echo -e "${RED}[-]${NC} $1"
}

log_verbose() {
  if [ "$VERBOSE" -eq 1 ]; then
    echo -e "$1"
  fi
}

sanitize_filename() {
  echo "$1" | tr -cd '[:alnum:]._-'
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

exec 2> "$OUTPUT_DIR/errors.log"

log_info "Starting scan for target: $TARGET"

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

if [ -s "$LIVE_HOSTS_FILE" ]; then
  while read -r host; do
    safe_host=$(sanitize_filename "$host")

    nmap -sS -F -Pn $COMMON_OPTS -oN "$OUTPUT_DIR/scan2_syn_${safe_host}.txt" "$host" && {
      increment_scan_count
      track_scan_status "scan2_syn_${safe_host}" "done"
    } || track_scan_status "scan2_syn_${safe_host}" "errored"

    nmap -sT -F -Pn $COMMON_OPTS -oN "$OUTPUT_DIR/scan2_connect_${safe_host}.txt" "$host" && {
      increment_scan_count
      track_scan_status "scan2_connect_${safe_host}" "done"
    } || track_scan_status "scan2_connect_${safe_host}" "errored"

    nmap -sU --top-ports 100 -Pn $COMMON_OPTS -oN "$OUTPUT_DIR/scan2_udp_${safe_host}.txt" "$host" && {
      increment_scan_count
      track_scan_status "scan2_udp_${safe_host}" "done"
    } || track_scan_status "scan2_udp_${safe_host}" "errored"

    TCP_PORTS=$(grep -Eh '^[0-9]+/tcp\s+open' "$OUTPUT_DIR/scan2_syn_${safe_host}.txt" "$OUTPUT_DIR/scan2_connect_${safe_host}.txt" 2>/dev/null | cut -d/ -f1 | sort -nu | paste -sd, -)
    if [ -n "$TCP_PORTS" ]; then
      echo "$TCP_PORTS" > "$OUTPUT_DIR/open_ports_tcp_${safe_host}.txt"
      log_success "TCP ports for $host: $TCP_PORTS"
    else
      rm -f "$OUTPUT_DIR/open_ports_tcp_${safe_host}.txt"
    fi

    UDP_PORTS=$(grep -Eh '^[0-9]+/udp\s+open' "$OUTPUT_DIR/scan2_udp_${safe_host}.txt" 2>/dev/null | cut -d/ -f1 | sort -nu | paste -sd, -)
    if [ -n "$UDP_PORTS" ]; then
      echo "$UDP_PORTS" > "$OUTPUT_DIR/open_ports_udp_${safe_host}.txt"
      log_success "UDP ports for $host: $UDP_PORTS"
    else
      rm -f "$OUTPUT_DIR/open_ports_udp_${safe_host}.txt"
    fi

    if [ -f "$OUTPUT_DIR/open_ports_tcp_${safe_host}.txt" ]; then
      PORTS=$(cat "$OUTPUT_DIR/open_ports_tcp_${safe_host}.txt")
      nmap -sS -Pn $COMMON_OPTS -p "$PORTS" -oN "$OUTPUT_DIR/scan3_syn_${safe_host}.txt" "$host" && track_scan_status "scan3_syn_${safe_host}" "done" || track_scan_status "scan3_syn_${safe_host}" "errored"
      nmap -sV -Pn $COMMON_OPTS -p "$PORTS" -oN "$OUTPUT_DIR/scan3_version_${safe_host}.txt" "$host" && track_scan_status "scan3_version_${safe_host}" "done" || track_scan_status "scan3_version_${safe_host}" "errored"
      nmap -sC -Pn $COMMON_OPTS -p "$PORTS" -oN "$OUTPUT_DIR/scan3_script_basic_${safe_host}.txt" "$host" && track_scan_status "scan3_script_basic_${safe_host}" "done" || track_scan_status "scan3_script_basic_${safe_host}" "errored"
      nmap -A -Pn $COMMON_OPTS -p "$PORTS" -oN "$OUTPUT_DIR/scan3_aggressive_${safe_host}.txt" "$host" && track_scan_status "scan3_aggressive_${safe_host}" "done" || track_scan_status "scan3_aggressive_${safe_host}" "errored"
    fi

    if [ -f "$OUTPUT_DIR/open_ports_udp_${safe_host}.txt" ]; then
      PORTS=$(cat "$OUTPUT_DIR/open_ports_udp_${safe_host}.txt")
      nmap -sU -Pn $COMMON_OPTS -p "$PORTS" -oN "$OUTPUT_DIR/scan3_udp_${safe_host}.txt" "$host" && track_scan_status "scan3_udp_${safe_host}" "done" || track_scan_status "scan3_udp_${safe_host}" "errored"
    fi

    nmap -O -Pn $COMMON_OPTS -oN "$OUTPUT_DIR/scan3_osdetect_${safe_host}.txt" "$host" && track_scan_status "scan3_osdetect_${safe_host}" "done" || track_scan_status "scan3_osdetect_${safe_host}" "errored"

    for script in vulners dns-brute dns-service-discovery smb-os-discovery smb-enum-shares smb-enum-users; do
      if [ -f "$OUTPUT_DIR/open_ports_tcp_${safe_host}.txt" ]; then
        PORTS=$(cat "$OUTPUT_DIR/open_ports_tcp_${safe_host}.txt")
        nmap --script "$script" -Pn $COMMON_OPTS -p "$PORTS" -oN "$OUTPUT_DIR/scan3_nse_${script}_${safe_host}.txt" "$host" && track_scan_status "scan3_nse_${script}_${safe_host}" "done" || track_scan_status "scan3_nse_${script}_${safe_host}" "errored"
      fi
    done

    nmap --traceroute -Pn $COMMON_OPTS -oN "$OUTPUT_DIR/scan3_trace_${safe_host}.txt" "$host" && track_scan_status "scan3_trace_${safe_host}" "done" || track_scan_status "scan3_trace_${safe_host}" "errored"
  done < "$LIVE_HOSTS_FILE"
else
  log_error "No live hosts discovered."
  exit 1
fi

# Step 4: Extract CVEs
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

touch "$OUTPUT_DIR/.done"

# Final Summary
log_info "Scan complete. Output saved to $OUTPUT_DIR"
echo "Live hosts: $LIVE_HOSTS_FILE"
echo "Scan status: $SCAN_TRACKER_FILE"
echo "CVEs (if any): $VULN_XML"
echo "Total scans: $SCAN_COUNTER"
echo "Done."
