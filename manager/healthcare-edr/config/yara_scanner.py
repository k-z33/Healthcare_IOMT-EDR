"""
YARA File Scanner
==================
Files ko YARA rules se scan karo — malware patterns detect karo.
Ubuntu VM mein run karo.

Objective: a.iii — File reputation analysis and unknown threat detection

Install: sudo apt install yara python3-yara
Run    : python3 yara_scanner.py /path/to/file_or_dir
"""

import os
import sys
import json
import hashlib
from datetime import datetime

try:
    import yara
except ImportError:
    print("❌ yara-python not installed")
    print("   sudo apt install python3-yara")
    sys.exit(1)

# ── Config ────────────────────────────────────────────────────────────────────
RULES_FILE  = os.path.join(os.path.dirname(__file__), "edr_rules.yar")
RESULTS_DIR = os.path.expanduser("~/edr-forensics/yara-results")
os.makedirs(RESULTS_DIR, exist_ok=True)


# ── Load Rules ────────────────────────────────────────────────────────────────
def load_rules():
    if not os.path.exists(RULES_FILE):
        print(f"❌ Rules file not found: {RULES_FILE}")
        sys.exit(1)
    rules = yara.compile(filepath=RULES_FILE)
    print(f"✅ YARA rules loaded: {RULES_FILE}")
    return rules


# ── Scan Single File ──────────────────────────────────────────────────────────
def scan_file(filepath: str, rules) -> dict:
    """
    One file ko scan karo.

    Returns
    -------
    dict with: file, sha256, verdict, severity, matches
    """
    if not os.path.isfile(filepath):
        return {"error": f"Not a file: {filepath}"}

    try:
        with open(filepath, "rb") as f:
            content = f.read()
    except PermissionError:
        return {"file": filepath, "error": "Permission denied"}

    sha256  = hashlib.sha256(content).hexdigest()
    matches = rules.match(data=content)

    result = {
        "file"     : filepath,
        "size"     : len(content),
        "sha256"   : sha256,
        "scanned"  : datetime.utcnow().isoformat(),
        "matches"  : [],
        "verdict"  : "CLEAN",
        "severity" : "LOW",
    }

    if not matches:
        return result

    # ── Process matches ───────────────────────────────────────────────────────
    result["verdict"] = "MALICIOUS"
    highest = "LOW"

    for m in matches:
        meta     = m.meta
        severity = meta.get("severity", "MEDIUM")
        result["matches"].append({
            "rule"        : m.rule,
            "severity"    : severity,
            "description" : meta.get("description", ""),
            "mitre"       : meta.get("mitre", ""),
            "strings"     : [str(s) for s in m.strings[:5]],   # top 5 hits
        })
        # Highest severity wins
        order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        if order.get(severity, 0) > order.get(highest, 0):
            highest = severity

    result["severity"] = highest
    return result


# ── Scan Directory ────────────────────────────────────────────────────────────
def scan_directory(dirpath: str, rules,
                   extensions: tuple = (".exe", ".dll", ".ps1", ".bat",
                                         ".sh", ".py", ".php", ".txt")):
    """Puri directory recursively scan karo"""
    all_results = []
    for root, _, files in os.walk(dirpath):
        for fname in files:
            if fname.endswith(extensions):
                fpath  = os.path.join(root, fname)
                result = scan_file(fpath, rules)
                all_results.append(result)
    return all_results


# ── Print Result ──────────────────────────────────────────────────────────────
def print_result(r: dict):
    if "error" in r:
        print(f"  ⚠️  {r.get('file', '?')} — {r['error']}")
        return

    icon = "⚠️ " if r["verdict"] == "MALICIOUS" else "✅"
    print(f"\n  {icon} {r['file']}")
    print(f"     SHA-256 : {r['sha256'][:32]}…")
    print(f"     Verdict : {r['verdict']}  [{r['severity']}]")

    for m in r["matches"]:
        print(f"     Rule    : {m['rule']}")
        print(f"     Desc    : {m['description']}")
        print(f"     MITRE   : {m['mitre']}")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print("=" * 55)
    print("  EDR YARA Scanner")
    print("=" * 55)

    rules    = load_rules()
    targets  = sys.argv[1:] if len(sys.argv) > 1 else ["/tmp"]

    all_results  = []
    malicious    = 0

    for target in targets:
        if os.path.isfile(target):
            r = scan_file(target, rules)
            all_results.append(r)
            print_result(r)
            if r.get("verdict") == "MALICIOUS":
                malicious += 1

        elif os.path.isdir(target):
            print(f"\n  Scanning directory: {target}")
            results = scan_directory(target, rules)
            for r in results:
                all_results.append(r)
                print_result(r)
                if r.get("verdict") == "MALICIOUS":
                    malicious += 1
        else:
            print(f"  ⚠️  Not found: {target}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 55)
    print(f"  Total scanned : {len(all_results)}")
    print(f"  Malicious     : {malicious}")
    print(f"  Clean         : {len(all_results) - malicious}")
    print("=" * 55)

    # ── Save results ──────────────────────────────────────────────────────────
    ts       = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(RESULTS_DIR, f"yara_scan_{ts}.json")
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n  Results saved: {out_path}")


if __name__ == "__main__":
    main()