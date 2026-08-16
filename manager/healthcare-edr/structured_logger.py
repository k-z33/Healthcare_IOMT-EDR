"""
structured_logger.py — Persistent, structured (JSON) logging for the
Healthcare IoMT EDR pipeline.

Drop this file into ~/healthcare-edr/ alongside live_edr_iomt.py.
Console output stays exactly as-is; this ADDS a searchable JSON log file
with daily rotation. Nothing in your existing print() calls needs to
change — just add the few lines shown in "Integration" below.

Log location: ~/healthcare-edr/logs/edr_events.jsonl (+ rotated .1, .2 ...)
"""
import json
import logging
import logging.handlers
import os
from datetime import datetime, timezone

LOG_DIR = os.path.expanduser("~/healthcare-edr/logs")
LOG_FILE = os.path.join(LOG_DIR, "edr_events.jsonl")


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "level": record.levelname,
            "logger": record.name,
        }
        # record.msg is expected to be a dict (structured event) or a string
        if isinstance(record.msg, dict):
            payload.update(record.msg)
        else:
            payload["message"] = record.getMessage()
        return json.dumps(payload, default=str)


def get_logger(name="iomt_edr"):
    """Call once per script. Returns a logger that writes structured JSON
    lines to LOG_FILE, rotating daily and keeping 30 days of history."""
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger(name)
    if logger.handlers:  # avoid duplicate handlers if called twice
        return logger
    logger.setLevel(logging.INFO)

    handler = logging.handlers.TimedRotatingFileHandler(
        LOG_FILE, when="midnight", backupCount=30, utc=True
    )
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.propagate = False  # don't also dump JSON onto the console
    return logger


def log_alert(logger, device_id, description, severity, technique_id=None,
              tactic=None, hipaa_cite=None, extra=None):
    """Log a detection/alert event as one structured JSON line."""
    event = {
        "event_type": "alert",
        "device_id": device_id,
        "description": description,
        "severity": severity,
        "mitre_technique": technique_id,
        "mitre_tactic": tactic,
        "hipaa_cite": hipaa_cite,
    }
    if extra:
        event.update(extra)
    logger.info(event)


def log_ml_prediction(logger, device_id, prediction, confidence,
                       anomaly_score=None, human_reviewed=False,
                       reviewer_override=None):
    """Log an ML-overlay prediction as a structured JSON line — this is
    the audit-trail hook used by Phase 7 (AI governance)."""
    event = {
        "event_type": "ml_prediction",
        "device_id": device_id,
        "predicted_category": prediction,
        "confidence": confidence,
        "anomaly_score": anomaly_score,
        "human_reviewed": human_reviewed,
        "reviewer_override": reviewer_override,
    }
    logger.info(event)


if __name__ == "__main__":
    # Quick self-test — run: python3 structured_logger.py
    log = get_logger()
    log_alert(log, device_id="ventilator-02", description="Test alert",
              severity="HIGH", technique_id="T0836",
              tactic="Impact (ICS/Medical)", hipaa_cite="§164.308(a)(6)")
    log_ml_prediction(log, device_id="ventilator-02", prediction="anomalous",
                       confidence=0.87, anomaly_score=-0.42,
                       human_reviewed=False)
    print(f"[✓] Self-test complete. Check: {LOG_FILE}")
    with open(LOG_FILE) as f:
        for line in f:
            print(line.strip())
