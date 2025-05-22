#!/bin/bash

# ====================================
# Pure Bash Nmap Scanner with Full Recon, UDP, SCTP, SMB, and CVE Extraction (No Python)
# Each host discovery and scan phase is run individually with separate outputs
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

# Step 1: Individual Host Discovery Scans
nmap -sn -PE "$OUTPUT_DIR/scan1_icmp_echo.txt" "$TARGET"
nmap -sn -PP $COMMON_OPTS -oN "$OUTPUT_DIR/scan1_icmp_timestamp.txt" "$TARGET"
nmap -sn -PM $COMMON_OPTS -oN "$OUTPUT_DIR/scan1_icmp_netmask.txt" "$TARGET"
nmap -sn -PS22,80,443 $COMMON_OPTS -oN "$OUTPUT_DIR/scan1_tcp_syn.txt" "$TARGET"
nmap -sn -PA22,80,443 $COMMON_OPTS -oN "$OUTPUT_DIR/scan1_tcp_ack.txt" "$TARGET"
nmap -sn -PO1,6,17 $COMMON_OPTS -oN "$OUTPUT_DIR/scan1_ipproto.txt" "$TARGET"
nmap -sn -PR $COMMON_OPTS -oN "$OUTPUT_DIR/scan1_arp.txt" "$TARGET"

# Merge live hosts
grep -h "Nmap scan report for" "$OUTPUT_DIR"/scan1_*.txt | awk '{print $NF}' | grep -Eo '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | sort -u > "$LIVE_HOSTS_FILE"

# Step 2: Fast TCP Scan per Host (Separate scans)
if [ -s "$LIVE_HOSTS_FILE" ]; then
  while read -r host; do
    nmap -sS -F -Pn $COMMON_OPTS -oN "$OUTPUT_DIR/scan2_syn_$host.txt" "$host"
    nmap -sT -F -Pn $COMMON_OPTS -oN "$OUTPUT_DIR/scan2_connect_$host.txt" "$host"
    grep -Eo '([0-9]{1,5})/tcp\s+open' "$OUTPUT_DIR/scan2_syn_$host.txt" "$OUTPUT_DIR/scan2_connect_$host.txt" | cut -d/ -f1 | sort -u | paste -sd, - - > "$OUTPUT_DIR/open_ports_$host.txt"
  done < "$LIVE_HOSTS_FILE"
else
  echo "[-] No live hosts discovered. Exiting."
  exit 1
fi

# Step 3: Full Detailed Scans per Host (Split per feature)
while read -r host; do
  PORTS=$(cat "$OUTPUT_DIR/open_ports_$host.txt")
  if [ -n "$PORTS" ]; then
    nmap -sS -Pn $COMMON_OPTS -p "$PORTS" -oN "$OUTPUT_DIR/scan3_syn_$host.txt" "$host"
    nmap -sU -Pn $COMMON_OPTS -p "$PORTS" -oN "$OUTPUT_DIR/scan3_udp_$host.txt" "$host"
    nmap -sY -Pn $COMMON_OPTS -p "$PORTS" -oN "$OUTPUT_DIR/scan3_sctp_$host.txt" "$host"
    nmap -sV -Pn $COMMON_OPTS -p "$PORTS" -oN "$OUTPUT_DIR/scan3_version_$host.txt" "$host"
    nmap -sC -Pn $COMMON_OPTS -p "$PORTS" -oN "$OUTPUT_DIR/scan3_script_basic_$host.txt" "$host"
    nmap -A  -Pn $COMMON_OPTS -p "$PORTS" -oN "$OUTPUT_DIR/scan3_aggressive_$host.txt" "$host"
    nmap -O  -Pn $COMMON_OPTS         -oN "$OUTPUT_DIR/scan3_osdetect_$host.txt" "$host"
    for script in vulners dns-brute dns-service-discovery smb-os-discovery smb-enum-shares smb-enum-users; do
      nmap --script "$script" -Pn $COMMON_OPTS -p "$PORTS" -oN "$OUTPUT_DIR/scan3_nse_${script}_$host.txt" "$host"
    done
    nmap --traceroute -Pn $COMMON_OPTS -p "$PORTS" -oN "$OUTPUT_DIR/scan3_trace_$host.txt" "$host"
  fi
done < "$LIVE_HOSTS_FILE"

# Step 4: Extract CVEs from all XMLs
VULN_XML="$OUTPUT_DIR/cve_hosts.xml"
echo "<vulnerabilities>" > "$VULN_XML"
if command -v xmlstarlet > /dev/null; then
  for xml in "$OUTPUT_DIR"/scan3_nse_*.xml; do
    [ -f "$xml" ] || continue
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
      "$xml" >> "$VULN_XML"
  done
fi
echo "</vulnerabilities>" >> "$VULN_XML"

# Summary
echo -e "\n=============================="
echo "Scan complete. Results saved in: $OUTPUT_DIR"
echo "Live hosts: $LIVE_HOSTS_FILE"
echo "Open ports: Individual files: open_ports_<host>.txt"
echo "Full scan outputs per type in: scan3_*_host.txt"
echo "CVE summary (XML): $VULN_XML"
echo "=============================="
