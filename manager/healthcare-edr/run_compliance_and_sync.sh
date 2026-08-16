#!/bin/bash
set -e

FORENSICS_HOST="ubuntu@172.31.33.186"
FORENSICS_DIR="~/forensics-tools/reports/compliance"

echo "[*] Marking current time..."
MARKER=$(mktemp)

echo "[*] Running compliance_report.py..."
cd ~/healthcare-edr
python3 config/compliance_report.py

echo "[*] Running live_complainace_iomt.py (HIPAA + HITRUST + NIST)..."
python3 live_complainace_iomt.py

echo "[*] Finding newly created report files..."
NEW_HTML=$(find ~/healthcare-edr/compliance_reports \( -name "*.html" -o -name "*.txt" \) -newer "$MARKER" 2>/dev/null)
NEW_JSON=$(find ~/edr-compliance-reports -name "*.json" -newer "$MARKER" 2>/dev/null)

rm -f "$MARKER"

if [ -z "$NEW_HTML" ] && [ -z "$NEW_JSON" ]; then
    echo "[!] No new files detected — nothing to sync."
    exit 0
fi

echo "[*] Ensuring remote directory exists..."
ssh "$FORENSICS_HOST" "mkdir -p $FORENSICS_DIR"

if [ -n "$NEW_HTML" ]; then
    echo "[*] Syncing HTML report(s)..."
    scp $NEW_HTML "$FORENSICS_HOST:$FORENSICS_DIR/"
fi

if [ -n "$NEW_JSON" ]; then
    echo "[*] Syncing JSON report(s)..."
    scp $NEW_JSON "$FORENSICS_HOST:$FORENSICS_DIR/"
fi

echo "[✓] Compliance reports generated and synced to Forensics: $FORENSICS_DIR"
