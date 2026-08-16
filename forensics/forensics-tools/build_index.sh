#!/bin/bash
REPORTS_DIR=~/forensics-tools/reports
{
echo "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>EDR Reports Index</title>"
echo "<style>body{font-family:sans-serif;background:#fdfcf8;padding:30px;max-width:900px;margin:auto}"
echo "h1{color:#1d3557}h2{color:#1d3557;border-bottom:2px solid #eef0f6;padding-bottom:6px;margin-top:30px}"
echo "ul{list-style:none;padding:0}li{padding:8px 0;border-bottom:1px solid #f1f3f9}"
echo "a{color:#4361ee;text-decoration:none}.meta{color:#7a7a85;font-size:12px}</style></head><body>"
echo "<h1>🏥 Healthcare IoMT EDR — All Reports</h1>"
echo "<p class='meta'>Last updated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')</p>"

echo "<h2>🔍 Forensic Analysis Reports</h2><ul>"
find "$REPORTS_DIR" -maxdepth 1 -name "report_*.html" -printf '%T@ %f\n' | sort -rn | while read ts fname; do
    dt=$(date -d @${ts%.*} '+%Y-%m-%d %H:%M')
    echo "<li><a href=\"$fname\">$fname</a> <span class='meta'>($dt)</span></li>"
done
echo "</ul>"

echo "<h2>📋 Case Investigation Reports</h2><ul>"
find "$REPORTS_DIR/investigations" -name "*.txt" -printf '%T@ %f\n' 2>/dev/null | sort -rn | while read ts fname; do
    dt=$(date -d @${ts%.*} '+%Y-%m-%d %H:%M')
    echo "<li><a href=\"investigations/$fname\">$fname</a> <span class='meta'>($dt)</span></li>"
done
echo "</ul>"

echo "<h2>✅ Compliance Reports</h2><ul>"
find "$REPORTS_DIR/compliance" -name "*.json" -printf '%T@ %f\n' 2>/dev/null | sort -rn | while read ts fname; do
    dt=$(date -d @${ts%.*} '+%Y-%m-%d %H:%M')
    echo "<li><a href=\"compliance/$fname\">$fname</a> <span class='meta'>($dt)</span></li>"
done
echo "</ul></body></html>"
} > "$REPORTS_DIR/index.html"
echo "[✓] Index rebuilt: $REPORTS_DIR/index.html"
