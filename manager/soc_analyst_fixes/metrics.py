#!/usr/bin/env python3
import json, os, statistics
from datetime import datetime, timezone

LOG_FILE = "soc_metrics.jsonl"
STAGES = ["attack_occurred", "alert_generated", "case_created", "containment_action"]

def log_stage(case_id, stage, timestamp=None):
    if stage not in STAGES:
        raise ValueError(f"Invalid stage: {stage}")
    entry = {
        "case_id": case_id,
        "stage": stage,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat()
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry

def report():
    if not os.path.exists(LOG_FILE):
        print("No metrics log found")
        return
    entries = []
    with open(LOG_FILE) as f:
        for line in f:
            if line.strip():
                entries.append(json.loads(line))
    case_ids = sorted(set(e["case_id"] for e in entries))
    print(f"\n=== SOC Response Time KPIs ===")
    print(f"Cases analyzed: {len(case_ids)}")
    for cid in case_ids:
        case_entries = {e["stage"]: e["timestamp"] for e in entries if e["case_id"] == cid}
        if "attack_occurred" in case_entries and "alert_generated" in case_entries:
            t1 = datetime.fromisoformat(case_entries["attack_occurred"])
            t2 = datetime.fromisoformat(case_entries["alert_generated"])
            print(f"{cid} MTTD: {(t2-t1).total_seconds():.2f} sec")

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", action="store_true")
    ap.add_argument("--case-id")
    ap.add_argument("--stage", choices=STAGES)
    ap.add_argument("--report", action="store_true")
    args = ap.parse_args()
    if args.log and args.case_id and args.stage:
        entry = log_stage(args.case_id, args.stage)
        print(json.dumps(entry, indent=2))
    elif args.report:
        report()
