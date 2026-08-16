#!/bin/bash
# create_index_pattern.sh — Creates the Kibana index pattern for the
# "iomt-alerts" index (populated by index_alerts_to_es.py).
# Run this AFTER index_alerts_to_es.py has shipped at least one alert
# (so the index exists) and AFTER Kibana is up.
set -euo pipefail

KIBANA_URL="http://localhost:5601"

echo "[*] Creating index pattern 'iomt-alerts*'..."
curl -s -X POST "${KIBANA_URL}/api/index_patterns/index_pattern" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{
    "index_pattern": {
      "title": "iomt-alerts*",
      "timeFieldName": "@timestamp"
    }
  }'

echo ""
echo "[✓] Index pattern created. Now import iomt_dashboard.ndjson:"
echo "    Kibana UI > Stack Management > Saved Objects > Import"
