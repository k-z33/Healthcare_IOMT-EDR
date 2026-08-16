#!/usr/bin/env bash
# atomic_validation.sh
# Independent validation — runs REAL technique-execution commands
# (not simulate_medical_device.py) against the Manager, to prove
# detections fire against genuine attacker behavior, not just the
# project's own simulated log events.
#
# Run this ON THE AGENT (172.31.27.110), targeting the Manager.
# Safe: read-only recon + intentionally-failed auth attempts only.
# No actual exploitation, no data modification.
#
# Usage: bash atomic_validation.sh <manager_ip> | tee atomic_validation_results.txt

MANAGER_IP="${1:-172.31.44.154}"
echo "=================================================================="
echo "ATOMIC-STYLE VALIDATION — targeting Manager at $MANAGER_IP"
echo "Started: $(date -u +'%Y-%m-%d %H:%M UTC')"
echo "=================================================================="

echo -e "\n--- [T1046] Network Service Discovery (port scan) ---"
echo ">> Expected to trigger: rule 100225 / 100235 (network_reconnaissance_scan / port_scan_detected)"
echo ">> NOTE: using -Pn (skip host-alive ping probe) + only Security-Group-confirmed-reachable ports"
if ! command -v nmap &> /dev/null; then
  echo "nmap not found — installing..."
  sudo apt-get install -y nmap -q
fi
nmap -sT -Pn -p 1514,1515,22,443,9000,9001,55000 "$MANAGER_IP" 2>&1 | tail -20

echo -e "\n--- [T1595] Active Scanning (broader sweep incl. closed ports) ---"
echo ">> Expected to trigger: rule 100241 (repeated_firewall_violations) if multiple ports blocked"
nmap -sT -Pn -p 3000-3010,7000-7010,8800-8810 "$MANAGER_IP" 2>&1 | tail -10

echo -e "\n--- [T1110] Brute Force (repeated failed auth) ---"
echo ">> Expected to trigger: rule 100226 (repeated_failed_authentication) — against Wazuh dashboard (443), confirmed reachable"
for i in $(seq 1 6); do
  curl -sk -u "admin:wrongpass$i" -o /dev/null -w "Attempt $i: HTTP %{http_code}\n" \
    --max-time 3 "https://$MANAGER_IP:443/"
  sleep 1
done

echo -e "\n--- [T1571] Non-Standard Port Usage ---"
echo ">> Expected to trigger: rule 100202 (unexpected_port_connection)"
for port in 4444 6667 8081 31337; do
  timeout 3 nc -zv -w2 "$MANAGER_IP" "$port" 2>&1
done

echo -e "\n--- [Additional] TheHive/Cortex reachability + auth probe ---"
echo ">> These ARE confirmed open (9000, 9001) — legitimate attack-surface test"
curl -sk -o /dev/null -w "TheHive (9000): HTTP %{http_code}\n" --max-time 3 "https://$MANAGER_IP:9000/"
curl -sk -o /dev/null -w "Cortex (9001):  HTTP %{http_code}\n" --max-time 3 "https://$MANAGER_IP:9001/"

echo -e "\n=================================================================="
echo "VALIDATION COMPLETE — $(date -u +'%Y-%m-%d %H:%M UTC')"
echo "=================================================================="
echo ""
echo "NEXT STEP: On the Manager, check whether these generated alerts:"
echo "  docker exec healthcare-edr-wazuh.manager-1 tail -100 /var/ossec/logs/alerts/alerts.json | grep -i '100202\\|100225\\|100226\\|100235\\|100241'"
echo "  (or check TheHive/Kibana for new cases/alerts in this time window)"
