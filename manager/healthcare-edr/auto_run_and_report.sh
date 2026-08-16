#!/bin/bash
CONTAINER="healthcare-edr-wazuh.manager-1"
ALERTS_FILE="/var/ossec/logs/alerts/alerts.json"
IDLE_SECONDS=5
FORENSICS_HOST="ubuntu@172.31.33.186"

cd ~/healthcare-edr
echo "[*] Starting live_edr_iomt.py..."
python3 live_edr_iomt.py > /tmp/live_edr_output.log 2>&1 &
EDR_PID=$!
echo "[*] PID: $EDR_PID — waiting for alerts to go idle..."

LAST_SIZE=-1
STABLE=0
while kill -0 $EDR_PID 2>/dev/null; do
    CUR=$(docker exec $CONTAINER wc -c < $ALERTS_FILE 2>/dev/null)
    if [ "$CUR" == "$LAST_SIZE" ]; then STABLE=$((STABLE+1)); else STABLE=0; fi
    LAST_SIZE=$CUR
    if [ "$STABLE" -ge "$IDLE_SECONDS" ]; then
        echo "[*] Idle ${IDLE_SECONDS}s — stopping live_edr_iomt.py..."
        kill -INT $EDR_PID
        break
    fi
    sleep 1
done
wait $EDR_PID 2>/dev/null

echo "--- Final stats ---"
tail -15 /tmp/live_edr_output.log

echo "[*] Generating + syncing compliance report..."
./run_compliance_and_sync.sh

echo "[*] Syncing investigation reports..."
NEW_INV=$(find ~/healthcare-edr/investigation_reports -name "*.txt" -newermt "-3 minutes" 2>/dev/null)
if [ -n "$NEW_INV" ]; then
    ssh $FORENSICS_HOST "mkdir -p ~/forensics-tools/reports/investigations"
    scp $NEW_INV $FORENSICS_HOST:~/forensics-tools/reports/investigations/
fi

echo "[*] Rebuilding report index on Forensics..."
ssh $FORENSICS_HOST "~/forensics-tools/build_index.sh"

echo "[✓] Investigation + compliance ready on Forensics NOW."
echo "    Forensic pcap report follows automatically in ~4 min (capture window)."
