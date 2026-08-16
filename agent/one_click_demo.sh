#!/bin/bash
echo "======================================"
echo "  Fresh Demo Run — sab kuch automatic"
echo "======================================"

echo "[1/3] Capture background mein shuru ho raha hai..."
cd ~
./capture_and_transfer.sh &
CAPTURE_PID=$!

sleep 5

echo "[2/3] Demo attacks fire ho rahe hain..."
./run_demo_attacks_iomt.sh

echo "[3/3] Attacks khatam. Capture apni 240s window poori karega, phir Forensics ko khud transfer hoga."
echo "      (yeh ~4 minute lega, khud khatam ho jayega)"
wait $CAPTURE_PID

echo ""
echo "✅ SAB KUCH DONE — pcap Forensics pe transfer ho chuka hai."
echo "   Ab Manager pe jaake live_edr_iomt.py band karein (Ctrl+C)"
echo "   agar woh chal raha ho, phir compliance sync karein."
