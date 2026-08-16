#!/usr/bin/env python3
"""
chain_of_custody.py

Tracks chain of custody for forensic evidence collected during an
incident (Velociraptor pcaps, memory dumps, log exports, etc.).

Design goals:
  - Append-only log (never edit/delete past entries — that's the whole point)
  - Every entry hashes the evidence file at that moment, so any later
    tampering is detectable (hash won't match)
  - Ties directly to a TheHive case_id so the CoC record is traceable
    back to the case that triggered the collection

Log file: chain_of_custody.jsonl  (one JSON object per line, append-only)

Typical flow:
  1. record_collection()  -> right after Velociraptor pulls evidence
  2. verify_integrity()   -> before running any analysis on the file
  3. record_transfer()    -> whenever the file moves hands/location
                             (e.g. SOC server -> analysis workstation)
  4. record_analysis()    -> after TShark/Volatility3 processes it
  5. generate_report()    -> produces the CoC table for the forensic report
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

LOG_FILE = os.environ.get("COC_LOG_FILE", "chain_of_custody.jsonl")


def _now():
    return datetime.now(timezone.utc).isoformat()


def _sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _append(entry):
    entry["logged_at"] = _now()
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def record_collection(case_id, evidence_path, collector, evidence_type, device_id=None, notes=""):
    """Call immediately after Velociraptor (or any tool) pulls evidence off a device."""
    if not os.path.exists(evidence_path):
        raise FileNotFoundError(evidence_path)
    entry = {
        "event": "collection",
        "case_id": case_id,
        "evidence_path": str(Path(evidence_path).resolve()),
        "evidence_type": evidence_type,          # e.g. "pcap", "memory_dump", "log_export"
        "sha256": _sha256(evidence_path),
        "collector": collector,                  # analyst name / tool identity
        "device_id": device_id,
        "notes": notes,
    }
    return _append(entry)


def record_transfer(case_id, evidence_path, from_custodian, to_custodian, method, notes=""):
    """Call whenever evidence changes hands/location (still same file, same hash expected)."""
    current_hash = _sha256(evidence_path)
    entry = {
        "event": "transfer",
        "case_id": case_id,
        "evidence_path": str(Path(evidence_path).resolve()),
        "sha256": current_hash,
        "from_custodian": from_custodian,
        "to_custodian": to_custodian,
        "method": method,                        # e.g. "scp", "physical USB", "internal network copy"
        "notes": notes,
    }
    return _append(entry)


def record_analysis(case_id, evidence_path, analyst, tool, findings_summary, notes=""):
    """Call after TShark / Volatility3 / any analysis tool processes the evidence."""
    current_hash = _sha256(evidence_path)
    entry = {
        "event": "analysis",
        "case_id": case_id,
        "evidence_path": str(Path(evidence_path).resolve()),
        "sha256": current_hash,
        "analyst": analyst,
        "tool": tool,
        "findings_summary": findings_summary,
        "notes": notes,
    }
    return _append(entry)


def verify_integrity(case_id, evidence_path):
    """
    Recomputes the hash and compares it against the FIRST (collection) entry
    for this file in this case. Returns (True, None) if unchanged,
    (False, details) if the hash has drifted -- i.e. possible tampering.
    """
    if not os.path.exists(LOG_FILE):
        return False, "No chain-of-custody log found"

    resolved = str(Path(evidence_path).resolve())
    original_hash = None
    with open(LOG_FILE) as f:
        for line in f:
            entry = json.loads(line)
            if entry["case_id"] == case_id and entry.get("evidence_path") == resolved \
               and entry["event"] == "collection":
                original_hash = entry["sha256"]
                break

    if original_hash is None:
        return False, "No collection record found for this evidence file"

    current_hash = _sha256(evidence_path)
    if current_hash != original_hash:
        return False, f"HASH MISMATCH — original {original_hash}, current {current_hash}"
    return True, None


def get_case_entries(case_id):
    """All CoC entries for a given case, in chronological order."""
    if not os.path.exists(LOG_FILE):
        return []
    entries = []
    with open(LOG_FILE) as f:
        for line in f:
            e = json.loads(line)
            if e["case_id"] == case_id:
                entries.append(e)
    return entries


def generate_report_html(case_id):
    """Returns an HTML <section> with the chain-of-custody table, ready to
    paste into the existing forensic report (see integration note below)."""
    entries = get_case_entries(case_id)
    if not entries:
        return f"<section><h2>Chain of Custody</h2><p>No custody records found for case {case_id}.</p></section>"

    rows = ""
    for e in entries:
        ok, detail = True, ""
        if e["event"] != "collection":
            ok, detail = verify_integrity(case_id, e["evidence_path"])
        integrity = "✅ Verified" if ok else f"⚠️ {detail}"
        rows += f"""<tr>
            <td>{e['logged_at']}</td>
            <td>{e['event']}</td>
            <td>{os.path.basename(e['evidence_path'])}</td>
            <td><code style="font-size:11px">{e['sha256'][:16]}...</code></td>
            <td>{e.get('collector') or e.get('analyst') or e.get('to_custodian','-')}</td>
            <td>{integrity}</td>
        </tr>"""

    return f"""
    <section>
      <h2>Chain of Custody — Case {case_id}</h2>
      <p>Evidence integrity is verified by SHA-256 hash comparison against the
      original collection record. Any mismatch below indicates the evidence
      file was modified after collection.</p>
      <table border="1" cellpadding="6" style="border-collapse:collapse;width:100%">
        <tr style="background:#1F4E5F;color:white">
          <th>Timestamp (UTC)</th><th>Event</th><th>Evidence</th>
          <th>SHA-256 (short)</th><th>Custodian</th><th>Integrity</th>
        </tr>
        {rows}
      </table>
    </section>
    """


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Chain of custody CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("collect")
    c.add_argument("--case-id", required=True)
    c.add_argument("--file", required=True)
    c.add_argument("--collector", required=True)
    c.add_argument("--type", required=True)
    c.add_argument("--device-id", default=None)

    v = sub.add_parser("verify")
    v.add_argument("--case-id", required=True)
    v.add_argument("--file", required=True)

    r = sub.add_parser("report")
    r.add_argument("--case-id", required=True)
    r.add_argument("--output", default=None)

    args = ap.parse_args()

    if args.cmd == "collect":
        entry = record_collection(args.case_id, args.file, args.collector, args.type, args.device_id)
        print(json.dumps(entry, indent=2))
    elif args.cmd == "verify":
        ok, detail = verify_integrity(args.case_id, args.file)
        print("VERIFIED" if ok else f"FAILED: {detail}")
    elif args.cmd == "report":
        html = generate_report_html(args.case_id)
        if args.output:
            with open(args.output, "w") as f:
                f.write(html)
            print(f"Written to {args.output}")
        else:
            print(html)
