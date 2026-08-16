#!/bin/bash
# setup_kibana.sh — Adds Kibana to the existing Forensics-box Elasticsearch
# (172.31.33.186:9200, already running for Cortex). No new Elasticsearch,
# no change to Cortex's config — this only ADDS a Kibana container that
# points at the same Elasticsearch instance.
#
# Run this ON THE FORENSICS BOX (172.31.33.186).
set -euo pipefail

ES_HOST="http://localhost:9200"
KIBANA_PORT="5601"

echo "[*] Checking Elasticsearch is reachable at ${ES_HOST}..."
if ! curl -s -o /dev/null -w "%{http_code}" "${ES_HOST}" | grep -q "200"; then
    echo "[!] ERROR: Elasticsearch not reachable at ${ES_HOST}. Aborting."
    echo "    Check: docker ps | grep elasticsearch"
    exit 1
fi
echo "[✓] Elasticsearch is up."

ES_VERSION=$(curl -s "${ES_HOST}" | python3 -c "import sys,json; print(json.load(sys.stdin)['version']['number'])")
echo "[*] Detected Elasticsearch version: ${ES_VERSION}"

echo "[*] Starting Kibana (version-matched to Elasticsearch)..."
docker run -d \
  --name iomt-kibana \
  --network host \
  -e "ELASTICSEARCH_HOSTS=${ES_HOST}" \
  docker.elastic.co/kibana/kibana:${ES_VERSION}

echo "[*] Waiting for Kibana to become ready (this can take ~60s)..."
for i in $(seq 1 30); do
    if curl -s -o /dev/null -w "%{http_code}" "http://localhost:${KIBANA_PORT}/api/status" | grep -q "200"; then
        echo "[✓] Kibana is up at http://<this-host-public-ip>:${KIBANA_PORT}"
        break
    fi
    sleep 5
done

echo ""
echo "[*] Next step: create the index pattern + import the starter dashboard:"
echo "    bash create_index_pattern.sh"
echo "    (then import iomt_dashboard.ndjson via Kibana UI: Stack Management > Saved Objects > Import)"
