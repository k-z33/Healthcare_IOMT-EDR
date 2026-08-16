#!/usr/bin/env python3
"""
view_all_reports.py

Unified report viewer — collects all reports from:
- Investigation reports (TheHive cases)
- Compliance reports (NIST/HIPAA/HITRUST)
- PCAP PHI/Credential scan reports (Forensics)
- Forensic analysis reports (Volatility/TShark)
- ML audit logs
- SOC metrics (MTTD/MTTR)

Usage:
  python3 view_all_reports.py
  python3 view_all_reports.py --latest 5   # Show only latest 5 reports per category
"""
import os
import json
import subprocess
from datetime import datetime
from pathlib import Path

FORENSICS_HOST = "172.31.33.186"
FORENSICS_USER = "ubuntu"

def get_file_mtime(filepath):
    """Get file modification time as formatted string."""
    try:
        mtime = os.path.getmtime(filepath)
        return datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
    except:
        return "Unknown"

def list_reports_in_dir(directory, pattern="*.html", report_type="Report", expand_user=True):
    """List all reports in a directory with timestamps."""
    if expand_user:
        directory = os.path.expanduser(directory)
    
    if not os.path.exists(directory):
        return []
    
    reports = []
    for f in Path(directory).glob(pattern):
        reports.append({
            "title": f.name,
            "path": str(f),
            "time": get_file_mtime(str(f)),
            "type": report_type,
            "location": "Manager"
        })
    
    # Sort by modification time (newest first)
    reports.sort(key=lambda x: x["time"], reverse=True)
    return reports

def list_remote_reports(remote_dir, pattern="*.html", report_type="Report"):
    """List reports on Forensics machine via SSH."""
    try:
        # SSH command to list files with timestamps
        cmd = f"ssh {FORENSICS_USER}@{FORENSICS_HOST} 'cd {remote_dir} && ls -lt {pattern} 2>/dev/null | head -20'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        
        if result.returncode != 0:
            return []
        
        reports = []
        for line in result.stdout.strip().split("\n"):
            if line.strip():
                parts = line.split()
                if len(parts) >= 9:
                    # Extract filename and timestamp
                    filename = parts[-1]
                    timestamp = " ".join(parts[5:8])
                    reports.append({
                        "title": filename,
                        "path": f"{FORENSICS_USER}@{FORENSICS_HOST}:{remote_dir}/{filename}",
                        "time": timestamp,
                        "type": report_type,
                        "location": "Forensics"
                    })
        return reports
    except Exception as e:
        print(f"   Warning: Could not fetch from Forensics ({e})")
        return []

def print_section(title, reports, max_show=None):
    """Print a section header and report list."""
    print(f"\n{'='*80}")
    print(f"📋 {title}")
    print(f"{'='*80}")
    
    if not reports:
        print("   No reports found.")
        return
    
    if max_show:
        reports = reports[:max_show]
    
    for i, report in enumerate(reports, 1):
        location_icon = "🖥️" if report["location"] == "Manager" else "🌐"
        print(f"\n{i}. {report['title']}")
        print(f"   Type: {report['type']}")
        print(f"   Generated: {report['time']}")
        print(f"   Location: {location_icon} {report['location']}")
        print(f"   Path: {report['path']}")

import argparse as _argparse
_arg_parser = _argparse.ArgumentParser()
_arg_parser.add_argument("--latest", type=int, default=None,
                          help="Show only latest N reports per category")
_ARGS, _ = _arg_parser.parse_known_args()

_original_print_section = print_section
def print_section(title, reports, max_show=None):
    if _ARGS.latest:
        max_show = _ARGS.latest
    return _original_print_section(title, reports, max_show)

def main():
    print("\n" + "="*80)
    print("🏥 Healthcare IoMT EDR — All Reports Viewer")
    print("="*80)
    print(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 1. Investigation Reports
    inv_reports = list_reports_in_dir(
        "~/healthcare-edr/investigation_reports",
        "*.html",
        "Investigation Report (TheHive Case)"
    )
    print_section("🔍 Investigation Reports (Auto-generated on Case Creation)", inv_reports, max_show=10)
    
    # 2. Compliance Reports
    comp_reports = list_reports_in_dir(
        "~/healthcare-edr/compliance_reports",
        "*.html",
        "Compliance Report (NIST/HIPAA/HITRUST)"
    )
    comp_reports_json = list_reports_in_dir(
        "~/edr-compliance-reports",
        "*.json",
        "Compliance Report (NIST/PCI-DSS/ISO27001 JSON)"
    )
    comp_reports = comp_reports + comp_reports_json
    comp_reports.sort(key=lambda x: x["time"], reverse=True)
    print_section("📜 Compliance Reports (NIST/HIPAA/HITRUST)", comp_reports, max_show=5)
    
    # 3. PCAP PHI/Credential Reports (Forensics - Local)
    pcap_reports_local = list_reports_in_dir(
        "~/pcap_reports",
        "*.txt",
        "PCAP PHI/Credential Scan",
        expand_user=True
    )
    
    # 3b. PCAP PHI/Credential Reports (Forensics - Remote)
    pcap_reports_remote = list_remote_reports(
        "~/pcap_reports",
        "*.txt",
        "PCAP PHI/Credential Scan"
    )
    
    pcap_reports = pcap_reports_local + pcap_reports_remote
    print_section("🔒 PCAP PHI/Credential Scan Reports (Forensics)", pcap_reports, max_show=10)
    
    # 4. Forensic Analysis Reports (Volatility/TShark) - Forensics Machine
    forensic_reports = list_remote_reports(
        "~/forensics-tools/reports",
        "*.html",
        "Forensic Analysis (Volatility/TShark)"
    )
    print_section("🔬 Forensic Analysis Reports (Volatility/TShark) [Forensics Machine]", forensic_reports, max_show=10)
    
    # 5. SOC Metrics Summary
    print_section("📊 SOC Metrics Summary", [])
    metrics_file = os.path.expanduser("~/healthcare-edr/soc_metrics.jsonl")
    if os.path.exists(metrics_file):
        with open(metrics_file) as f:
            entries = [json.loads(l) for l in f if l.strip()]
        case_ids = sorted(set(e["case_id"] for e in entries))
        print(f"\n   Total Cases Logged: {len(case_ids)}")
        print(f"   Metrics File: {metrics_file}")
        print(f"   Latest Entry Time: {get_file_mtime(metrics_file)}")
    
    # 6. ML Audit Log Summary
    print_section("🤖 ML Audit Log Summary", [])
    ml_log_file = os.path.expanduser("~/healthcare-edr/logs/edr_events.jsonl")
    if os.path.exists(ml_log_file):
        ml_count = 0
        with open(ml_log_file) as f:
            for line in f:
                if "ml_prediction" in line:
                    ml_count += 1
        print(f"\n   ML Predictions Logged: {ml_count}")
        print(f"   Log File: {ml_log_file}")
        print(f"   Last Modified: {get_file_mtime(ml_log_file)}")
    
    # 7. Quick Stats
    print(f"\n{'='*80}")
    print("📈 Quick Stats")
    print(f"{'='*80}")
    total_reports = len(inv_reports) + len(comp_reports) + len(pcap_reports) + len(forensic_reports)
    print(f"\n   Total Reports: {total_reports}")
    print(f"   - Investigation Reports: {len(inv_reports)}")
    print(f"   - Compliance Reports: {len(comp_reports)}")
    print(f"   - PCAP PHI/Credential Reports: {len(pcap_reports)}")
    print(f"   - Forensic Analysis Reports: {len(forensic_reports)}")
    print(f"   - SOC Cases: {len(case_ids) if os.path.exists(metrics_file) else 0}")
    print(f"   - ML Predictions: {ml_count if os.path.exists(ml_log_file) else 0}")
    
    print(f"\n{'='*80}")
    print("💡 Tips:")
    print("   - Open HTML report: firefox <report_path>")
    print("   - Open Forensics report: ssh ubuntu@172.31.33.186 'firefox <path>'")
    print("   - View latest only: python3 view_all_reports.py --latest 5")
    print(f"{'='*80}\n")

if __name__ == "__main__":
    main()
