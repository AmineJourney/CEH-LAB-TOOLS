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

LIVE_COUNT=$(wc -l < "$LIVE_HOSTS_FILE")
echo "[*] Found $LIVE_COUNT live hosts."

if [[ "$LIVE_COUNT" -eq 0 ]]; then
    echo "[!] No live hosts found. Exiting."
    exit 0
fi

# ========== STEP 2: PARALLEL PORT SCANNING ==========
scan_ports() {
    local ip="$1"
    echo "[*] Scanning top 1000 TCP ports on $ip..."
    local outfile="$OUTDIR/02_ports_$ip.txt"
    
    nmap -sT -Pn -n -T3 --open --max-retries 2 "$ip" -oN "$outfile" || {
        echo "[!] Scan failed for $ip" >&2
        return
    }

    if grep -q '^[0-9]' "$outfile"; then
        grep '^[0-9]' "$outfile" | cut -d '/' -f1 | tr '\n' ',' | sed 's/,$/\n/' | awk -v ip="$ip" '{print ip":"$0}' >> "$OPEN_PORTS_FILE"
    else
        echo "[*] No open ports found on $ip"
    fi
}
export -f scan_ports

echo "[*] Running parallel port scans (top 1000 ports)..."
parallel -j 2 scan_ports :::: "$LIVE_HOSTS_FILE"

# ========== SAFEGUARD: Check for port scan results ==========
if [[ ! -s "$OPEN_PORTS_FILE" ]]; then
    echo "[!] No open ports detected on any host. Exiting."
    exit 0
fi

# ========== STEP 3: OS DETECTION AND TTL ==========
os_detect_and_ttl() {
    local ip="$1"
    echo "[*] Detecting OS for $ip..."
    local os_file="$OUTDIR/03_os_$ip.txt"

    nmap -O -Pn -n -T3 "$ip" -oN "$os_file"

    local ttl=128
    if grep -qi 'linux' "$os_file"; then ttl=64;
    elif grep -qi 'windows' "$os_file"; then ttl=128;
    elif grep -qi 'cisco\|router' "$os_file"; then ttl=255;
    elif grep -qi 'mac os' "$os_file"; then ttl=64;
    fi

    ports=$(grep "$ip" "$OPEN_PORTS_FILE" | cut -d ':' -f2)
    echo "$ip:$ports:$ttl" >> "$TTL_FILE"
}
export -f os_detect_and_ttl

cut -d ':' -f1 "$OPEN_PORTS_FILE" | parallel -j 2 os_detect_and_ttl

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
done | parallel -j 2 --colsep ':' deep_scan {1} {2} {3}

# ========== DONE ==========
echo "[*] Lab scan complete. Results saved in: $OUTDIR"
