#!/bin/bash

# ========== CONFIGURATION ==========
TARGET_SUBNET="$1"
if [[ -z "$TARGET_SUBNET" ]]; then
    echo "Usage: $0 <target_subnet>"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTDIR="lab_fullscan_$TIMESTAMP"
mkdir -p "$OUTDIR"

LIVE_HOSTS_FILE="$OUTDIR/live_hosts.txt"
OPEN_PORTS_FILE="$OUTDIR/open_ports.txt"
TTL_FILE="$OUTDIR/ttl_by_host.txt"
DEEP_SCAN_LOG="$OUTDIR/deep_scan_log.txt"

set -euo pipefail

# ========== TOOL CHECKS ==========
for cmd in nmap parallel; do
    command -v "$cmd" >/dev/null || { echo "[!] Required command '$cmd' not found."; exit 1; }
done

# ========== STEP 1: HOST DISCOVERY ==========
echo "[*] Discovering live hosts in $TARGET_SUBNET..."
nmap -sn -Pn "$TARGET_SUBNET" -n --data-length 50 -T3 -oG "$OUTDIR/01_ping_sweep.gnmap"
grep Up "$OUTDIR/01_ping_sweep.gnmap" | awk '{print $2}' > "$LIVE_HOSTS_FILE"
echo "[*] Found $(wc -l < "$LIVE_HOSTS_FILE") live hosts."

# ========== STEP 2: PARALLEL PORT SCANNING ==========
scan_ports() {
    local ip="$1"
    echo "[*] Scanning all TCP ports on $ip..."
    nmap -sT -Pn -n -T3 -p- --open --max-retries 2 "$ip" -oN "$OUTDIR/02_ports_$ip.txt"
    grep '^[0-9]' "$OUTDIR/02_ports_$ip.txt" | cut -d '/' -f1 | tr '\n' ',' | sed 's/,$/\n/' | awk -v ip="$ip" '{print ip":"$0}' >> "$OPEN_PORTS_FILE"
}
export -f scan_ports

parallel -j 5 scan_ports :::: "$LIVE_HOSTS_FILE"

# ========== STEP 3: OS DETECTION AND TTL ==========
os_detect_and_ttl() {
    local ip="$1"
    echo "[*] Detecting OS and TTL for $ip..."
    nmap -O -Pn -n -T3 "$ip" -oN "$OUTDIR/03_os_$ip.txt"

    local ttl=128
    if grep -qi 'linux' "$OUTDIR/03_os_$ip.txt"; then ttl=64;
    elif grep -qi 'windows' "$OUTDIR/03_os_$ip.txt"; then ttl=128;
    elif grep -qi 'cisco\|router' "$OUTDIR/03_os_$ip.txt"; then ttl=255;
    elif grep -qi 'mac os' "$OUTDIR/03_os_$ip.txt"; then ttl=64;
    fi

    ports=$(grep "$ip" "$OPEN_PORTS_FILE" | cut -d ':' -f2)
    echo "$ip:$ports:$ttl" >> "$TTL_FILE"
}
export -f os_detect_and_ttl

cut -d ':' -f1 "$OPEN_PORTS_FILE" | parallel -j 5 os_detect_and_ttl

# ========== STEP 4: DEEP SCAN ==========
deep_scan() {
    local ip="$1"
    local ports="$2"
    local ttl="$3"
    echo "[*] Running deep scan on $ip with TTL $ttl and ports $ports..."
    nmap -sT -Pn -n -T4 --ttl "$ttl" -sV -A --script=default,vuln -p "$ports" "$ip" -oN "$OUTDIR/04_deep_$ip.txt"
    echo "$ip scanned with TTL $ttl on ports $ports" >> "$DEEP_SCAN_LOG"
}
export -f deep_scan

cat "$TTL_FILE" | while IFS=':' read -r ip ports ttl; do
    echo "$ip:$ports:$ttl"
done | parallel -j 5 --colsep ':' deep_scan {1} {2} {3}

# ========== DONE ==========
echo "[*] Lab scan complete. Results saved in: $OUTDIR"
