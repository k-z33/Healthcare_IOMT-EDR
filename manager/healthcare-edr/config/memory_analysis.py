"""
Automated Memory Forensics — Volatility 3
==========================================
Memory dump pe 5 plugins chalata hai aur JSON report banata hai.
Ubuntu VM mein run karo.

Objective: b.ii — Memory analysis and artifact extraction with Volatility

Install karo pehle:
  cd /opt
  git clone https://github.com/volatilityfoundation/volatility3.git
  cd volatility3
  pip3 install -r requirements.txt

Run:
  python3 memory_analysis.py /path/to/memory.lime CASE-001
"""

import os
import sys
import json
import hashlib
import subprocess
from datetime import datetime

# ── Configuration ─────────────────────────────────────────────────────────────
VOLATILITY_PATH = "/opt/volatility3/vol.py"
PYTHON          = sys.executable          # current python3
REPORTS_DIR     = os.path.expanduser("~/edr-forensics/reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


# ── Helpers ───────────────────────────────────────────────────────────────────
def sha256_of_file(path: str) -> str:
    """Chain of custody ke liye SHA-256 hash"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def run_plugin(memory_file: str, plugin: str,
               timeout: int = 180) -> tuple[str, bool]:
    """
    Single Volatility plugin run karo.

    Returns
    -------
    (output_text, success_bool)
    """
    cmd = [PYTHON, VOLATILITY_PATH, "-f", memory_file, plugin]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            return result.stdout, True
        return result.stderr[:500], False
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT after {timeout}s]", False
    except FileNotFoundError:
        return "[ERROR] Volatility not found at " + VOLATILITY_PATH, False


# ── Main Analysis ─────────────────────────────────────────────────────────────
def analyze(memory_file: str, case_id: str) -> dict:
    """
    Complete memory forensics — 6 plugins:
      1. pslist   — process list
      2. pstree   — process tree (parent–child)
      3. malfind  — injected code / fileless malware  ← most important
      4. netscan  — active network connections
      5. cmdline  — command-line arguments
      6. ssdt     — SSDT hooks (rootkit indicator)

    Returns
    -------
    dict — full forensic report
    """
    if not os.path.exists(memory_file):
        print(f"❌ Memory file not found: {memory_file}")
        sys.exit(1)

    file_size = os.path.getsize(memory_file)
    file_hash = sha256_of_file(memory_file)

    print("=" * 60)
    print("  MEMORY FORENSICS REPORT")
    print("=" * 60)
    print(f"  Case ID   : {case_id}")
    print(f"  File      : {memory_file}")
    print(f"  Size      : {file_size / (1024**2):.1f} MB")
    print(f"  SHA-256   : {file_hash[:32]}…")
    print(f"  Analyst   : Kinat Zahra Khalil — EDR Platform")
    print(f"  Time (UTC): {datetime.utcnow().isoformat()}")
    print("=" * 60)

    report = {
        "case_id"     : case_id,
        "memory_file" : memory_file,
        "file_sha256" : file_hash,
        "file_size_mb": round(file_size / (1024**2), 2),
        "analyst"     : "Kinat Zahra Khalil",
        "timestamp"   : datetime.utcnow().isoformat(),
        "plugins"     : {},
        "iocs"        : [],
        "risk_score"  : 0,
        "verdict"     : "CLEAN",
    }

    # ── PLUGINS ───────────────────────────────────────────────────────────────
    plugins = {
        "windows.pslist" : ("Process List",
                            "Running processes — look for unsigned / unusual names"),
        "windows.pstree" : ("Process Tree",
                            "Parent–child relationships — cmd spawned by Word = suspicious"),
        "windows.malfind": ("Code Injection",
                            "rwx memory regions with PE headers = fileless malware"),
        "windows.netscan": ("Network Connections",
                            "Active connections — external IPs at unusual times"),
        "windows.cmdline": ("Command Lines",
                            "Look for -EncodedCommand, IEX, DownloadString"),
        "windows.ssdt"   : ("SSDT Hooks",
                            "Modified system call table = rootkit indicator"),
    }

    for plugin, (desc, note) in plugins.items():
        print(f"\n[*] {desc}")
        print(f"    Note: {note}")
        output, ok = run_plugin(memory_file, plugin)
        report["plugins"][plugin] = {
            "description": desc,
            "output"     : output,
            "success"    : ok,
        }

        # ── Risk scoring ──────────────────────────────────────────────────────
        if plugin == "windows.malfind" and ok:
            # PE header (MZ) in a non-image memory region = injection
            mz_count = output.count("4d 5a")   # MZ in hex
            if mz_count > 0:
                print(f"    ⚠️  {mz_count} PE header(s) in memory — possible injection!")
                report["risk_score"] += mz_count * 20
                report["iocs"].append(
                    f"code_injection: {mz_count} PE regions detected"
                )

        elif plugin == "windows.netscan" and ok:
            lines = [l for l in output.splitlines()
                     if "ESTABLISHED" in l or "CLOSE_WAIT" in l]
            external = [
                l for l in lines
                if not any(x in l for x in
                           ("10.", "192.168.", "172.", "127.", "0.0.0.0"))
            ]
            if external:
                print(f"    ⚠️  {len(external)} external connection(s) found")
                report["risk_score"] += len(external) * 10
                for conn_line in external[:3]:
                    report["iocs"].append(f"external_connection: {conn_line.strip()[:80]}")

        elif plugin == "windows.cmdline" and ok:
            suspicious_keywords = [
                "-encodedcommand", "downloadstring", "iex",
                "invoke-expression", "-bypass", "mimikatz",
                "-nop", "-windowstyle hidden",
            ]
            lower_out = output.lower()
            for kw in suspicious_keywords:
                if kw in lower_out:
                    print(f"    ⚠️  Suspicious keyword: {kw}")
                    report["risk_score"] += 15
                    report["iocs"].append(f"suspicious_cmdline: {kw}")

        elif plugin == "windows.ssdt" and ok:
            # SSDT output should be minimal; large output = hooks
            if len(output.strip()) > 500:
                print("    ⚠️  SSDT entries found — possible rootkit!")
                report["risk_score"] += 50
                report["iocs"].append("ssdt_hook: possible rootkit detected")

    # ── Verdict ───────────────────────────────────────────────────────────────
    if report["risk_score"] >= 50:
        report["verdict"] = "MALICIOUS"
    elif report["risk_score"] >= 20:
        report["verdict"] = "SUSPICIOUS"
    else:
        report["verdict"] = "CLEAN"

    print("\n" + "=" * 60)
    print(f"  VERDICT     : {report['verdict']}")
    print(f"  Risk Score  : {report['risk_score']} / 100")
    print(f"  IOCs found  : {len(report['iocs'])}")
    for ioc in report["iocs"]:
        print(f"    → {ioc}")
    print("=" * 60)

    # ── Save report ───────────────────────────────────────────────────────────
    ts       = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(REPORTS_DIR, f"{case_id}_{ts}.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  Report saved: {out_path}")

    return report


# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("\nUsage: python3 memory_analysis.py <memory_file> <case_id>")
        print("\nExample:")
        print("  python3 memory_analysis.py /tmp/ubuntu.lime CASE-2026-001")
        print("\nTo capture Ubuntu memory (run as root):")
        print("  cd /tmp/LiME/src && sudo insmod lime.ko 'path=/tmp/ubuntu.lime format=lime'")
        print("  sudo rmmod lime")
        sys.exit(0)

    analyze(sys.argv[1], sys.argv[2])