#!/bin/bash
WATCH_DIR="/home/ubuntu/pcap_captures"
PROCESSED_LOG="/home/ubuntu/forensics-tools/processed.log"
REPORT_URL_BASE="http://54.175.191.191:8090"
mkdir -p "$WATCH_DIR"
touch "$PROCESSED_LOG"

echo "[*] Watching $WATCH_DIR for new .pcap files..."

inotifywait -m -e close_write -e moved_to --format '%f' "$WATCH_DIR" | while read FILENAME
do
    if [[ "$FILENAME" == *.pcap ]]; then
        if grep -qxF "$FILENAME" "$PROCESSED_LOG"; then
            continue
        fi
        echo "[*] New capture detected: $FILENAME"
        sleep 2
        REPORT_PATH=$(python3 /home/ubuntu/forensics-tools/generate_report.py "$WATCH_DIR/$FILENAME" | tail -1 | sed 's/.*: //')
        REPORT_FILENAME=$(basename "$REPORT_PATH")
        echo "$FILENAME" >> "$PROCESSED_LOG"
        echo ""
        echo "=========================================="
        echo "  ✅ REPORT READY"
        echo "  Click/open this link in your browser:"
        echo "  ${REPORT_URL_BASE}/${REPORT_FILENAME}"
        echo "=========================================="
        echo ""
    fi
done
