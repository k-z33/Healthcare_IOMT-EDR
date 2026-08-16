"""
EDR Main Orchestrator
======================
Elasticsearch se new Wazuh alerts poll karta hai → ML analysis →
severity-based auto-response → TheHive case creation.

Objective: c.ii  — Automated threat containment
           c.iii — Adaptive response policies
           d.i   — SIEM integration

Run: python3 edr_orchestrator.py
"""

import sys
import time
import logging
import threading
import requests
import urllib3
from datetime     import datetime
from elasticsearch import Elasticsearch

# Sibling modules (same folder mein hona chahiye)
sys.path.append("../ml_model")
sys.path.append("../soar")
sys.path.append("../threat_intel")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("edr_orchestrator.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
CONFIG = {
    # Elasticsearch (Wazuh indexer)
    "es_url"       : "https://localhost:9200",
    "es_user"      : "admin",
    "es_pass"      : "SecretPassword",

    # ML API (ml_api.py)
    "ml_api_url"   : "http://localhost:8080",

    # Wazuh Manager API
    "wazuh_url"    : "https://localhost:55000",
    "wazuh_user"   : "wazuh-wui",
    "wazuh_pass"   : "MyS3cr37P450r.*-",

    # Poll interval (seconds)
    "poll_interval": 30,

    # Only process alerts at or above this level
    "min_level"    : 7,
}

# ── Elasticsearch Client ──────────────────────────────────────────────────────
es = Elasticsearch(
    CONFIG["es_url"],
    basic_auth=(CONFIG["es_user"], CONFIG["es_pass"]),
    verify_certs=False,
)


# ── Helpers ───────────────────────────────────────────────────────────────────
def alert_to_features(alert: dict) -> list:
    """
    Wazuh alert dict → 8 ML features.
    Same logic as feature_extractor.py (copied here to avoid import issues).
    """
    now        = datetime.utcnow()
    hour       = now.hour
    rule_level = int(alert.get("rule", {}).get("level", 0))
    src_ip     = alert.get("data", {}).get("srcip", "")
    decoder    = alert.get("decoder", {})
    groups_str = str(alert.get("rule", {}).get("groups", []))

    private = ("10.", "192.168.", "172.", "127.", "::", "0.0.0.0")
    ext     = 0 if (not src_ip or any(src_ip.startswith(p) for p in private)) else 1

    return [
        float(rule_level),
        float(hour),
        1.0 if 8 <= hour <= 18 else 0.0,
        1.0 if src_ip else 0.0,
        float(ext),
        1.0 if decoder.get("name") == "syscheck" else 0.0,
        1.0 if "authentication" in groups_str else 0.0,
        1.0 if rule_level >= 12 else 0.0,
    ]


def get_wazuh_token() -> str | None:
    """Wazuh API JWT token lao"""
    try:
        r = requests.post(
            f"{CONFIG['wazuh_url']}/security/user/authenticate",
            auth=(CONFIG["wazuh_user"], CONFIG["wazuh_pass"]),
            verify=False,
            timeout=5,
        )
        return r.json().get("data", {}).get("token")
    except Exception as e:
        log.warning(f"Wazuh auth failed: {e}")
        return None


def isolate_endpoint(agent_id: str, token: str) -> bool:
    """
    Wazuh active-response se endpoint quarantine karo.
    firewall-drop rule sab outbound traffic block karta hai.
    Objective: c.ii — Automated threat containment
    """
    r = requests.put(
        f"{CONFIG['wazuh_url']}/active-response",
        headers={"Authorization": f"Bearer {token}"},
        verify=False,
        timeout=10,
        json={
            "command"    : "!firewall-drop",
            "alert"      : {"data": {"srcip": "0.0.0.0"}},
            "agent_list" : [agent_id],
        },
    )
    ok = r.status_code == 200
    log.info(f"{'✅' if ok else '❌'} Isolate agent {agent_id}")
    return ok


def call_ml_api(features: list) -> dict:
    """ML /predict endpoint call karo"""
    try:
        r = requests.post(
            f"{CONFIG['ml_api_url']}/predict",
            json={"features": features},
            timeout=5,
        )
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        log.warning(f"ML API unreachable: {e}")

    # Fallback — rule_level based severity
    return {"severity": "LOW", "verdict": "NORMAL",
            "anomaly_score": 0.0, "threat_type": "BENIGN",
            "action": "LOG_ONLY", "confidence": 0.0}


# ── Core Processing ───────────────────────────────────────────────────────────
def process_alert(alert: dict):
    """
    Single alert ka complete lifecycle:
    1. ML analysis
    2. Severity decision (adaptive policy)
    3. Auto-contain if CRITICAL
    4. TheHive alert/case if HIGH+
    5. Elasticsearch update
    """
    rule_level = alert.get("rule", {}).get("level", 0)
    agent_name = alert.get("agent", {}).get("name", "unknown")
    agent_id   = alert.get("agent", {}).get("id", "000")
    rule_desc  = alert.get("rule", {}).get("description", "")

    log.info(f"Processing | agent={agent_name} | level={rule_level} | {rule_desc[:60]}")

    # ── Step 1: ML Analysis ───────────────────────────────────────────────────
    features  = alert_to_features(alert)
    ml_result = call_ml_api(features)

    # ── Step 2: Adaptive Severity Policy (Objective c.iii) ────────────────────
    # Rule level can override ML severity upward (never downward)
    severity = ml_result.get("severity", "LOW")
    if rule_level >= 15:
        severity = "CRITICAL"
    elif rule_level >= 12 and severity not in ("CRITICAL",):
        severity = "HIGH"

    ml_result["severity"] = severity
    log.info(f"  Verdict | {severity} | {ml_result.get('threat_type')} | "
             f"score={ml_result.get('anomaly_score', 0):.3f}")

    # ── Step 3: Auto-Containment (CRITICAL only) ──────────────────────────────
    contained = False
    if severity == "CRITICAL":
        log.warning(f"🚨 CRITICAL — Auto-containing {agent_name} ({agent_id})")
        token = get_wazuh_token()
        if token:
            contained = isolate_endpoint(agent_id, token)

    # ── Step 4: TheHive Alert/Case (HIGH+) ────────────────────────────────────
    if severity in ("CRITICAL", "HIGH"):
        try:
            from thehive_integration import create_alert
            create_alert(alert, ml_result)
        except ImportError:
            log.warning("thehive_integration not importable — check path")
        except Exception as e:
            log.error(f"TheHive error: {e}")

    # ── Step 5: Update Elasticsearch record ──────────────────────────────────
    idx = alert.get("_index")
    doc = alert.get("_id")
    if idx and doc:
        try:
            es.update(
                index=idx,
                id=doc,
                body={"doc": {
                    "edr_processed"   : True,
                    "edr_severity"    : severity,
                    "edr_threat_type" : ml_result.get("threat_type"),
                    "edr_score"       : ml_result.get("anomaly_score", 0),
                    "edr_contained"   : contained,
                    "edr_action"      : ml_result.get("action"),
                    "edr_timestamp"   : datetime.utcnow().isoformat(),
                }},
            )
        except Exception:
            pass   # Non-critical — don't break main flow


# ── Main Poll Loop ────────────────────────────────────────────────────────────
def main():
    log.info("=" * 55)
    log.info("  EDR Orchestrator started")
    log.info(f"  Poll interval  : {CONFIG['poll_interval']}s")
    log.info(f"  Min alert level: {CONFIG['min_level']}")
    log.info("=" * 55)

    last_ts = datetime.utcnow().isoformat()

    while True:
        try:
            # Fetch new unprocessed alerts
            query = {
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"@timestamp"  : {"gt": last_ts}}},
                            {"range": {"rule.level"  : {"gte": CONFIG["min_level"]}}},
                        ],
                        "must_not": [
                            # Skip already-processed alerts
                            {"exists": {"field": "edr_processed"}},
                        ],
                    }
                },
                "sort": [{"@timestamp": "asc"}],
                "size": 100,
            }

            result = es.search(index="wazuh-alerts-*", body=query)
            hits   = result["hits"]["hits"]

            if hits:
                log.info(f"Found {len(hits)} new alert(s)")
                for hit in hits:
                    alert         = hit["_source"]
                    alert["_index"] = hit["_index"]
                    alert["_id"]    = hit["_id"]

                    # Process each alert in a separate thread
                    t = threading.Thread(target=process_alert, args=(alert,))
                    t.daemon = True
                    t.start()

                # Advance timestamp to avoid reprocessing
                last_ts = hits[-1]["_source"]["@timestamp"]
            else:
                log.debug(f"No new alerts — sleeping {CONFIG['poll_interval']}s")

        except Exception as e:
            log.error(f"Orchestrator loop error: {e}")

        time.sleep(CONFIG["poll_interval"])


if __name__ == "__main__":
    main()