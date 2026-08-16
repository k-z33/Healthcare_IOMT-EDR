#!/usr/bin/env python3
"""
threat_intel_enrichment.py

Lightweight threat-intel enrichment using free-tier public APIs —
functionally replaces what a full Cortex + MISP deployment would do
(IOC reputation lookup), without the infra weight (Cortex was blocked
by an arm64/amd64 Docker incompatibility; full MISP was ruled out by
RAM constraints on the same host).

Supports:
  - AbuseIPDB (IP reputation) — free tier: 1000 checks/day
  - VirusTotal (IP/hash/domain reputation) — free tier: 4 req/min

Set API keys as environment variables (do NOT hardcode them):
  export ABUSEIPDB_API_KEY="..."
  export VIRUSTOTAL_API_KEY="..."

Usage as library (call from thehive_integration.py when a case is created):
  from threat_intel_enrichment import enrich_ip
  result = enrich_ip("203.0.113.42")

CLI:
  python3 threat_intel_enrichment.py ip 203.0.113.42
  python3 threat_intel_enrichment.py hash <sha256>
"""
import os
import time
import requests

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY")
VT_KEY = os.environ.get("VIRUSTOTAL_API_KEY")

_last_vt_call = 0


def _rate_limit_vt():
    """VirusTotal free tier: 4 requests/minute — space calls out."""
    global _last_vt_call
    elapsed = time.time() - _last_vt_call
    if elapsed < 16:
        time.sleep(16 - elapsed)
    _last_vt_call = time.time()


def check_abuseipdb(ip):
    if not ABUSEIPDB_KEY:
        return {"source": "abuseipdb", "error": "ABUSEIPDB_API_KEY not set"}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=10,
        )
        r.raise_for_status()
        data = r.json().get("data", {})
        return {
            "source": "abuseipdb",
            "ip": ip,
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "is_whitelisted": data.get("isWhitelisted"),
            "verdict": "malicious" if (data.get("abuseConfidenceScore") or 0) > 50 else "benign_or_unknown",
        }
    except requests.RequestException as e:
        return {"source": "abuseipdb", "ip": ip, "error": str(e)}


def check_virustotal_ip(ip):
    if not VT_KEY:
        return {"source": "virustotal", "error": "VIRUSTOTAL_API_KEY not set"}
    try:
        _rate_limit_vt()
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VT_KEY},
            timeout=10,
        )
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        return {
            "source": "virustotal",
            "ip": ip,
            "malicious_votes": malicious,
            "suspicious_votes": stats.get("suspicious", 0),
            "harmless_votes": stats.get("harmless", 0),
            "verdict": "malicious" if malicious > 0 else "benign_or_unknown",
        }
    except requests.RequestException as e:
        return {"source": "virustotal", "ip": ip, "error": str(e)}


def check_virustotal_hash(file_hash):
    if not VT_KEY:
        return {"source": "virustotal", "error": "VIRUSTOTAL_API_KEY not set"}
    try:
        _rate_limit_vt()
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": VT_KEY},
            timeout=10,
        )
        if r.status_code == 404:
            return {"source": "virustotal", "hash": file_hash, "verdict": "not_found"}
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        return {
            "source": "virustotal",
            "hash": file_hash,
            "malicious_votes": malicious,
            "verdict": "malicious" if malicious > 0 else "benign_or_unknown",
        }
    except requests.RequestException as e:
        return {"source": "virustotal", "hash": file_hash, "error": str(e)}


def enrich_ip(ip, use_virustotal=True):
    """Combined lookup — call this from thehive_integration.py per-alert."""
    results = [check_abuseipdb(ip)]
    if use_virustotal and VT_KEY:
        results.append(check_virustotal_ip(ip))

    verdicts = [r.get("verdict") for r in results if "verdict" in r]
    overall = "malicious" if "malicious" in verdicts else "benign_or_unknown"

    return {
        "ip": ip,
        "overall_verdict": overall,
        "sources": results,
    }


if __name__ == "__main__":
    import argparse, json
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    ip_p = sub.add_parser("ip")
    ip_p.add_argument("value")

    hash_p = sub.add_parser("hash")
    hash_p.add_argument("value")

    args = ap.parse_args()
    if args.cmd == "ip":
        print(json.dumps(enrich_ip(args.value), indent=2))
    elif args.cmd == "hash":
        print(json.dumps(check_virustotal_hash(args.value), indent=2))
