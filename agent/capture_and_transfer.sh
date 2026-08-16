#!/bin/bash
set -uo pipefail

FORENSICS_HOST="172.31.33.186"
FORENSICS_USER="ubuntu"
SSH_KEY="$HOME/.ssh/agent_to_forensics"
REMOTE_DIR="/home/ubuntu/pcap_captures"
LOCAL_DIR="/tmp/pcap_captures"
CAPTURE_DURATION="${1:-240}"   # seconds, default 240

mkdir -p "$LOCAL_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
FILENAME="demo_attack_${TIMESTAMP}.pcap"
LOCAL_FILE="${LOCAL_DIR}/${FILENAME}"

echo "[*] Ensuring remote directory exists..."
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "${FORENSICS_USER}@${FORENSICS_HOST}" "mkdir -p ${REMOTE_DIR}"

echo "[*] Starting capture: $LOCAL_FILE (duration: ${CAPTURE_DURATION}s)"
sudo timeout "$CAPTURE_DURATION" tcpdump -i any -w "$LOCAL_FILE" &
TCPDUMP_PID=$!

echo "[*] Capture running (PID $TCPDUMP_PID). Run your demo attack now."
wait $TCPDUMP_PID

if [ ! -f "$LOCAL_FILE" ]; then
    echo "[!] ERROR: Capture file was not created. Aborting."
    exit 1
fi

LOCAL_SIZE=$(stat -c%s "$LOCAL_FILE")
echo "[*] Capture complete. Local size: ${LOCAL_SIZE} bytes"

echo "[*] Transferring to Forensics Box..."
if scp -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "$LOCAL_FILE" "${FORENSICS_USER}@${FORENSICS_HOST}:${REMOTE_DIR}/${FILENAME}"; then
    echo "[*] SCP command succeeded. Verifying remote file..."
else
    echo "[!] ERROR: SCP transfer failed. Local file KEPT at: $LOCAL_FILE"
    exit 1
fi

REMOTE_SIZE=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "${FORENSICS_USER}@${FORENSICS_HOST}" "stat -c%s ${REMOTE_DIR}/${FILENAME} 2>/dev/null")

if [ -z "$REMOTE_SIZE" ]; then
    echo "[!] ERROR: Could not verify remote file exists. Local file KEPT at: $LOCAL_FILE"
    exit 1
fi

if [ "$LOCAL_SIZE" != "$REMOTE_SIZE" ]; then
    echo "[!] ERROR: Size mismatch (local=$LOCAL_SIZE remote=$REMOTE_SIZE). Local file KEPT at: $LOCAL_FILE"
    exit 1
fi

echo "[*] Verified: remote file matches local (size=${REMOTE_SIZE} bytes). Deleting local copy..."
rm -f "$LOCAL_FILE"
echo "[✓] Done. File safely on Forensics Box: ${REMOTE_DIR}/${FILENAME}"
