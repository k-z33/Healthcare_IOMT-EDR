"""
index_alerts_to_es.py — Ships Wazuh alerts (Manager box) into the
existing Elasticsearch on the Forensics box, under index "iomt-alerts",
so Kibana has real data to visualize.

WHY THIS IS NEEDED: the Forensics-box Elasticsearch currently only backs
Cortex's job/report storage — Wazuh alerts are not indexed there. Kibana
alone can't show alert data that was never shipped to Elasticsearch.
This script is the missing bridge. Run it on the MANAGER box
(172.31.44.154), where the Wazuh Docker container lives.

Run once manually to backfill, then add to cron for ongoing shipping:
    */5 * * * * /usr/bin/python3 ~/healthcare-edr/index_alerts_to_es.py >> ~/healthcare-edr/logs/es_shipper.log 2>&1
"""
import subprocess
import json
import urllib.request
import os
from datetime import datetime

CONTAINER = "healthcare-edr-wazuh.manager-1"
ES_URL = "http://172.31.33.186:9200"   # Forensics box, internal VPC IP
INDEX = "iomt-alerts"
STATE_FILE = os.path.expanduser("~/healthcare-edr/.es_shipper_last_count")


def get_docker_alerts(limit=200):
    try:
        cmd = ["docker", "exec", CONTAINER,
               "tail", f"-{limit * 3}",
               "/var/ossec/logs/alerts/alerts.json"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        alerts = []
        for line in result.stdout.strip().split('\n'):
            try:
                alerts.append(json.loads(line.strip()))
            except Exception:
                continue
        return alerts[-limit:]
    except Exception as e:
        print(f"[!] Failed to read Wazuh alerts: {e}")
        return []


def to_es_doc(a):
    level = int(a.get('rule', {}).get('level', 0))
    severity = "CRITICAL" if level >= 15 else "HIGH" if level >= 12 else \
        "MEDIUM" if level >= 7 else "LOW"
    return {
        "@timestamp": a.get("timestamp") or datetime.utcnow().isoformat() + "Z",
        "device_id": a.get('data', {}).get('device_id', 'unknown'),
        "description": a.get('rule', {}).get('description', 'unknown'),
        "level": level,
        "severity": severity,
        "rule_id": a.get('rule', {}).get('id'),
    }


def bulk_index(docs):
    if not docs:
        print("[*] No alerts to ship.")
        return
    lines = []
    for doc in docs:
        lines.append(json.dumps({"index": {"_index": INDEX}}))
        lines.append(json.dumps(doc))
    body = ("\n".join(lines) + "\n").encode("utf-8")

    req = urllib.request.Request(
        f"{ES_URL}/_bulk",
        data=body,
        headers={"Content-Type": "application/x-ndjson"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read())
            errors = result.get("errors", False)
            print(f"[✓] Shipped {len(docs)} alerts to {ES_URL}/{INDEX} "
                  f"(errors: {errors})")
    except Exception as e:
        print(f"[!] Failed to index into Elasticsearch: {e}")


if __name__ == "__main__":
    alerts = get_docker_alerts(limit=200)
    docs = [to_es_doc(a) for a in alerts]
    bulk_index(docs)
