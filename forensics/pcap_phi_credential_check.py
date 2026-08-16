#!/usr/bin/env python3
"""
6.3 — Pcap Cleartext PHI & Credential Leak Checker
Scans pcap files for:
  - HTTP Basic Auth / cleartext passwords
  - Common PHI patterns (MRN, Patient ID, SSN-like, DOB, names near medical terms)
  - Unencrypted sensitive protocols
Produces a clean, human-readable report.
"""

import subprocess
import re
import sys
import datetime
from pathlib import Path
from collections import defaultdict

REPORT_DIR = Path("pcap_reports")
REPORT_DIR.mkdir(exist_ok=True)

# Patterns
BASIC_AUTH_RE = re.compile(r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', re.I)
PASSWORD_RE = re.compile(r'(password|passwd|pwd|pass)\s*[=:]\s*([^\s&"\']{3,})', re.I)
USER_RE = re.compile(r'(username|user|login|userid)\s*[=:]\s*([^\s&"\']{2,})', re.I)

# PHI-ish patterns (heuristic — not perfect, but practical for demo)
MRN_RE = re.compile(r'\b(MRN|Medical[_\s]?Record[_\s]?No|Patient[_\s]?ID)[=:\s#]*([A-Z0-9\-]{5,15})\b', re.I)
SSN_RE = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
DOB_RE = re.compile(r'\b(DOB|Date[_\s]?of[_\s]?Birth)[=:\s]*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b', re.I)
PHI_KEYWORDS = re.compile(r'\b(patient|diagnosis|medication|prescription|allerg|ssn|mrn|phi|hipaa)\b', re.I)

def run_tshark(pcap: str, display_filter: str = "", fields: list = None) -> str:
    cmd = ["tshark", "-r", pcap, "-T", "fields"]
    if display_filter:
        cmd.extend(["-Y", display_filter])
    if fields:
        for f in fields:
            cmd.extend(["-e", f])
    else:
        cmd.extend(["-e", "frame.number", "-e", "ip.src", "-e", "ip.dst", "-e", "http.request.uri", "-e", "http.authorization", "-e", "http.file_data", "-e", "data.text"])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return result.stdout
    except Exception as e:
        return f"ERROR: {e}"

def extract_http_objects(pcap: str) -> str:
    """Get HTTP request/response lines that may contain cleartext."""
    cmd = ["tshark", "-r", pcap, "-Y", "http", "-T", "fields",
           "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst",
           "-e", "http.request.method", "-e", "http.request.uri",
           "-e", "http.authorization", "-e", "http.file_data"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return result.stdout
    except Exception as e:
        return ""

def scan_pcap(pcap_path: str) -> dict:
    pcap = Path(pcap_path)
    findings = {
        "file": str(pcap),
        "size_kb": round(pcap.stat().st_size / 1024, 1),
        "basic_auth": [],
        "cleartext_passwords": [],
        "usernames": [],
        "phi_patterns": [],
        "http_requests": 0,
        "notes": []
    }

    # 1. HTTP layer
    http_out = extract_http_objects(str(pcap))
    if http_out:
        lines = [l for l in http_out.strip().splitlines() if l.strip()]
        findings["http_requests"] = len(lines)

        for line in lines:
            # Basic Auth
            for m in BASIC_AUTH_RE.finditer(line):
                findings["basic_auth"].append(m.group(0)[:80])

            # Password fields
            for m in PASSWORD_RE.finditer(line):
                findings["cleartext_passwords"].append(f"{m.group(1)}={m.group(2)[:20]}...")

            # Usernames
            for m in USER_RE.finditer(line):
                findings["usernames"].append(f"{m.group(1)}={m.group(2)[:30]}")

            # PHI patterns
            for m in MRN_RE.finditer(line):
                findings["phi_patterns"].append(f"MRN/PatientID: {m.group(0)[:60]}")
            for m in SSN_RE.finditer(line):
                findings["phi_patterns"].append(f"SSN-like: {m.group(0)}")
            for m in DOB_RE.finditer(line):
                findings["phi_patterns"].append(f"DOB: {m.group(0)[:40]}")
            if PHI_KEYWORDS.search(line) and len(line) > 20:
                findings["phi_patterns"].append(f"PHI keyword context: {line[:80]}...")

    # 2. Also search raw data text for patterns (broader)
    raw = run_tshark(str(pcap), fields=["data.text", "http.file_data"])
    for m in BASIC_AUTH_RE.finditer(raw):
        findings["basic_auth"].append(m.group(0)[:80])
    for m in PASSWORD_RE.finditer(raw):
        findings["cleartext_passwords"].append(f"{m.group(1)}={m.group(2)[:20]}")
    for m in MRN_RE.finditer(raw):
        findings["phi_patterns"].append(f"MRN: {m.group(0)[:50]}")
    for m in SSN_RE.finditer(raw):
        findings["phi_patterns"].append(f"SSN-like: {m.group(0)}")

    # Dedupe
    for k in ["basic_auth", "cleartext_passwords", "usernames", "phi_patterns"]:
        findings[k] = list(dict.fromkeys(findings[k]))[:15]  # unique, max 15

    if not any([findings["basic_auth"], findings["cleartext_passwords"], findings["phi_patterns"]]):
        findings["notes"].append("No cleartext credentials or strong PHI patterns found in HTTP/data layers.")
        findings["notes"].append("This is expected if the demo traffic used encrypted channels or non-HTTP protocols.")

    return findings

def generate_report(findings: dict) -> str:
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    risk = "HIGH" if (findings["basic_auth"] or findings["cleartext_passwords"] or findings["phi_patterns"]) else "LOW"

    report = f"""
================================================================================
          PCAP CLEARTEXT PHI & CREDENTIAL LEAK CHECK (6.3)
================================================================================
Generated     : {now}
File          : {findings['file']}
Size          : {findings['size_kb']} KB
HTTP Requests : {findings['http_requests']}
Overall Risk  : {risk}

--------------------------------------------------------------------------------
1. CLEARTEXT CREDENTIALS
--------------------------------------------------------------------------------
"""
    if findings["basic_auth"]:
        report += "HTTP Basic Authentication headers found:\n"
        for item in findings["basic_auth"]:
            report += f"  • {item}\n"
    else:
        report += "  No HTTP Basic Auth headers detected.\n"

    if findings["cleartext_passwords"]:
        report += "\nCleartext password fields found:\n"
        for item in findings["cleartext_passwords"]:
            report += f"  • {item}\n"
    else:
        report += "\n  No cleartext password fields detected.\n"

    if findings["usernames"]:
        report += "\nUsernames observed:\n"
        for item in findings["usernames"][:8]:
            report += f"  • {item}\n"

    report += f"""
--------------------------------------------------------------------------------
2. POTENTIAL PHI EXPOSURE
--------------------------------------------------------------------------------
"""
    if findings["phi_patterns"]:
        for item in findings["phi_patterns"]:
            report += f"  • {item}\n"
    else:
        report += "  No strong PHI patterns (MRN / SSN / DOB) detected in cleartext.\n"

    report += f"""
--------------------------------------------------------------------------------
3. NOTES & RECOMMENDATIONS
--------------------------------------------------------------------------------
"""
    for note in findings["notes"]:
        report += f"  • {note}\n"

    report += """
  • Prefer TLS 1.2+ for all clinical device communications.
  • Disable HTTP Basic Auth on any management interfaces.
  • Ensure DICOM / HL7 interfaces are encrypted or isolated.
  • Any confirmed PHI in cleartext must be treated as a HIPAA incident.

================================================================================
IoMT-EDR Platform | Forensics node
================================================================================
"""
    return report.strip()

def main():
    if len(sys.argv) < 2:
        # Default: scan the newest demo pcap
        pcaps = sorted(Path("pcap_captures").glob("*.pcap"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not pcaps:
            print("No pcap files found in pcap_captures/")
            sys.exit(1)
        target = str(pcaps[0])
        print(f"[*] No file given — using newest: {target}")
    else:
        target = sys.argv[1]

    print(f"[*] Scanning: {target}")
    findings = scan_pcap(target)
    report = generate_report(findings)

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = REPORT_DIR / f"phi_credential_check_{ts}.txt"
    out.write_text(report)
    print(report)
    print(f"\n[+] Report saved: {out}")

if __name__ == "__main__":
    main()
