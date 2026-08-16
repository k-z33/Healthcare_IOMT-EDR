#!/usr/bin/env python3
"""
metrics.py

Tracks SOC response-time metrics: MTTD (Mean Time To Detect),
MTTC (Mean Time To Case-creation), MTTR (Mean Time To Response/Containment).

Records timestamps at each pipeline stage, keyed by case_id, and
computes the industry-standard KPIs SOC teams report.

Log file: soc_metrics.jsonl (append-only, one event per line)

Pipeline stages to log:
  attack_occurred   -> when the attack actually started (from simulate_medical_device.py)
  alert_generated   -> when Wazuh raised the alert
  case_created      -> when TheHive case was opened
  containment_action -> when auto_contain.py took action

Usage as a library (import into live_edr.py / auto_contain.py):
  from metrics import log_stage
  log_stage(case_id="CASE-001", stage="alert_generated")

CLI report:
  python3 metrics.py report
  python3 metrics.py report --since 2026-08-01
"""
import json
import os
import statistics
from datetime import datetime, timezone

LOG_FILE = os.environ.get("METRICS_LOG_FILE", "soc_metrics.jsonl")

STAGE_ORDER = ["attack_occurred", "alert_generated", "case_created", "containment_action"]


def _now():
    return datetime.now(timezone.utc).isoformat()


def log_stage(case_id, stage, device_id=None, notes=""):
    if stage not in STAGE_ORDER:
        raise ValueError(f"stage must be one of {STAGE_ORDER}")
    entry = {
        "case_id": case_id,
        "stage": stage,
        "device_id": device_id,
        "notes": notes,
        "timestamp": _now(),
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def _load_all():
    if not os.path.exists(LOG_FILE):
        return []
    entries = []
    with open(LOG_FILE) as f:
        for line in f:
            if line.strip():
                entries.append(json.loads(line))
    return entries


def compute_case_timings(case_id, entries=None):
    """Returns per-case elapsed seconds between consecutive stages."""
    entries = entries or _load_all()
    case_entries = {e["stage"]: e["timestamp"] for e in entries if e["case_id"] == case_id}

    def parse(ts):
        return datetime.fromisoformat(ts)

    timings = {}
    if "attack_occurred" in case_entries and "alert_generated" in case_entries:
        timings["detect_seconds"] = (parse(case_entries["alert_generated"]) - parse(case_entries["attack_occurred"])).total_seconds()
    if "alert_generated" in case_entries and "case_created" in case_entries:
        timings["case_seconds"] = (parse(case_entries["case_created"]) - parse(case_entries["alert_generated"])).total_seconds()
    if "case_created" in case_entries and "containment_action" in case_entries:
        timings["respond_seconds"] = (parse(case_entries["containment_action"]) - parse(case_entries["case_created"])).total_seconds()
    if "attack_occurred" in case_entries and "containment_action" in case_entries:
        timings["total_seconds"] = (parse(case_entries["containment_action"]) - parse(case_entries["attack_occurred"])).total_seconds()
    return timings


def compute_aggregate_kpis(since=None):
    entries = _load_all()
    if since:
        since_dt = datetime.fromisoformat(since).replace(tzinfo=timezone.utc)
        entries = [e for e in entries if datetime.fromisoformat(e["timestamp"]) >= since_dt]

    case_ids = sorted(set(e["case_id"] for e in entries))
    all_timings = [compute_case_timings(cid, entries) for cid in case_ids]

    def avg(key):
        vals = [t[key] for t in all_timings if key in t]
        return round(statistics.mean(vals), 2) if vals else None

    return {
        "cases_analyzed": len(case_ids),
        "MTTD_seconds": avg("detect_seconds"),      # Mean Time To Detect
        "MTTD_to_case_seconds": avg("case_seconds"), # Mean Time To Case creation
        "MTTR_seconds": avg("respond_seconds"),      # Mean Time To Respond/contain
        "MTT_total_seconds": avg("total_seconds"),   # Mean end-to-end
    }


def print_report(since=None):
    kpis = compute_aggregate_kpis(since)
    print("\n=== SOC Response Time KPIs ===")
    print(f"Cases analyzed        : {kpis['cases_analyzed']}")
    print(f"MTTD (attack->alert)  : {kpis['MTTD_seconds']} sec" if kpis['MTTD_seconds'] is not None else "MTTD                  : insufficient data")
    print(f"Alert->Case time      : {kpis['MTTD_to_case_seconds']} sec" if kpis['MTTD_to_case_seconds'] is not None else "Alert->Case time       : insufficient data")
    print(f"MTTR (case->contain)  : {kpis['MTTR_seconds']} sec" if kpis['MTTR_seconds'] is not None else "MTTR                   : insufficient data")
    print(f"Total (attack->contain): {kpis['MTT_total_seconds']} sec" if kpis['MTT_total_seconds'] is not None else "Total                   : insufficient data")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    log = sub.add_parser("log")
    log.add_argument("--case-id", required=True)
    log.add_argument("--stage", required=True, choices=STAGE_ORDER)
    log.add_argument("--device-id", default=None)

    rep = sub.add_parser("report")
    rep.add_argument("--since", default=None, help="ISO date, e.g. 2026-08-01")

    args = ap.parse_args()
    if args.cmd == "log":
        entry = log_stage(args.case_id, args.stage, args.device_id)
        print(json.dumps(entry, indent=2))
    elif args.cmd == "report":
        print_report(args.since)
