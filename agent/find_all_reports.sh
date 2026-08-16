#!/usr/bin/env bash
echo "=== MANAGER REPORTS ===" > /tmp/all_reports_summary.txt
find ~/healthcare-edr -type f \( -name "*.html" -o -name "*.txt" -o -name "*.pdf" -o -name "*.json" \) 2>/dev/null | grep -iE "report|investigat|compli|forensic|phi|pcap" >> /tmp/all_reports_summary.txt

echo "" >> /tmp/all_reports_summary.txt
echo "=== FORENSICS REPORTS (if mounted/accessible) ===" >> /tmp/all_reports_summary.txt
find ~ -type f \( -name "*.html" -o -name "*.txt" -o -name "*.pdf" -o -name "*.json" \) 2>/dev/null | grep -iE "report|forensic|phi|pcap" >> /tmp/all_reports_summary.txt
