#!/usr/bin/env python3
import subprocess, json, os
from datetime import datetime
from pathlib import Path

RESET = '\033[0m'; BOLD = '\033[1m'; DIM = '\033[2m'
RED = '\033[38;5;203m'; GREEN = '\033[38;5;83m'; YELLOW = '\033[38;5;220m'
CYAN = '\033[38;5;51m'; MAGENTA = '\033[38;5;213m'; BLUE = '\033[38;5;75m'
WHITE = '\033[97m'; ORANGE = '\033[38;5;208m'; PURPLE = '\033[38;5;141m'

FORENSICS_HOST = "172.31.33.186"
FORENSICS_USER = "ubuntu"

def sep(): print(f"{DIM}{CYAN}{'─'*78}{RESET}")

def section_header(icon, title, color):
    print()
    print(f"{color}╔{'═'*76}╗{RESET}")
    print(f"{color}║{RESET} {icon}  {BOLD}{WHITE}{title}{RESET}")
    print(f"{color}╚{'═'*76}╝{RESET}")

def get_file_mtime(filepath):
    try:
        return datetime.fromtimestamp(os.path.getmtime(filepath)).strftime("%Y-%m-%d %H:%M:%S")
    except:
        return "Unknown"

def list_reports_in_dir(directory, pattern, expand_user=True):
    if expand_user:
        directory = os.path.expanduser(directory)
    if not os.path.exists(directory):
        return []
    reports = []
    for f in Path(directory).glob(pattern):
        reports.append({"title": f.name, "path": str(f), "time": get_file_mtime(str(f))})
    reports.sort(key=lambda x: x["time"], reverse=True)
    return reports

def list_remote_reports(remote_dir, pattern):
    try:
        cmd = f"ssh {FORENSICS_USER}@{FORENSICS_HOST} 'cd {remote_dir} && ls -lt {pattern} 2>/dev/null | head -20'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return []
        reports = []
        for line in result.stdout.strip().split("\n"):
            if line.strip():
                parts = line.split()
                if len(parts) >= 9:
                    filename = parts[-1]
                    timestamp = " ".join(parts[5:8])
                    reports.append({"title": filename, "path": f"{remote_dir}/{filename}", "time": timestamp})
        return reports
    except Exception:
        return []

def print_reports(reports, limit=5, icon="📄"):
    if not reports:
        print(f"   {DIM}No reports found.{RESET}")
        return
    for r in reports[:limit]:
        print(f"   {GREEN}▸{RESET} {BOLD}{WHITE}{r['title']}{RESET}")
        print(f"     {DIM}🕒 {r['time']}{RESET}")

# ── Header ──────────────────────────────────────────────────────────
print(f"\n{BOLD}{WHITE}")
print("   🏥  H E A L T H C A R E   I o M T   E D R")
print(f"{RESET}{DIM}      All Reports Dashboard · Manager + Forensics{RESET}")
print(f"{DIM}      Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
sep()

# ── Investigation ───────────────────────────────────────────────────
inv = list_reports_in_dir("~/healthcare-edr/investigation_reports", "*.html")
section_header("🔍", "INVESTIGATION REPORTS (TheHive Cases)", CYAN)
print_reports(inv, 5)

# ── Compliance: HIPAA / HITRUST (live, healthcare-focused) ────────────
hipaa_txt = list_reports_in_dir("~/healthcare-edr/compliance_reports", "live_report_*.txt")
hipaa_html = list_reports_in_dir("~/healthcare-edr/compliance_reports", "compliance_report_*.html")
hipaa = sorted(hipaa_txt + hipaa_html, key=lambda x: x["time"], reverse=True)
section_header("🏥", "HIPAA / HITRUST COMPLIANCE (Live — IoMT Healthcare)", CYAN)
print_reports(hipaa, 3)
if hipaa_txt:
    try:
        with open(hipaa_txt[0]["path"]) as f:
            txt = f.read()
        for line in txt.splitlines():
            if "HIPAA Safeguards" in line or "HITRUST Domains" in line or "Total Alerts" in line:
                print(f"   {DIM}{line.strip()}{RESET}")
    except Exception:
        pass

# ── Compliance: NIST / PCI-DSS / ISO 27001 (industry frameworks) ──────
comp_json = list_reports_in_dir("~/edr-compliance-reports", "*.json")
section_header("📜", "INDUSTRY COMPLIANCE (NIST CSF · PCI-DSS · ISO 27001)", GREEN)
print_reports(comp_json, 5)
comp = hipaa + comp_json

# ── PCAP PHI/Credential ────────────────────────────────────────────
phi_remote = list_remote_reports("~/pcap_reports", "*.txt")
section_header("🔒", "PCAP PHI / CREDENTIAL SCAN", ORANGE)
print_reports(phi_remote, 5)

# ── Forensic ─────────────────────────────────────────────────────────
forensic = list_remote_reports("~/forensics-tools/reports", "*.html")
section_header("🔬", "FORENSIC ANALYSIS (TShark + Volatility3)", PURPLE)
print_reports(forensic, 5)

# ── SOC Metrics ──────────────────────────────────────────────────────
section_header("📊", "SOC METRICS SUMMARY", MAGENTA)
metrics_file = os.path.expanduser("~/healthcare-edr/soc_metrics.jsonl")
if os.path.exists(metrics_file):
    with open(metrics_file) as f:
        entries = [json.loads(l) for l in f if l.strip()]
    case_ids = sorted(set(e["case_id"] for e in entries))
    print(f"   {YELLOW}📁 Total Cases Logged{RESET}   {WHITE}{BOLD}{len(case_ids)}{RESET}")
    print(f"   {YELLOW}🕒 Latest Entry{RESET}         {get_file_mtime(metrics_file)}")

# ── ML Audit ─────────────────────────────────────────────────────────
section_header("🤖", "ML AUDIT LOG SUMMARY", BLUE)
ml_log_file = os.path.expanduser("~/healthcare-edr/logs/edr_events.jsonl")
ml_count = 0
if os.path.exists(ml_log_file):
    with open(ml_log_file) as f:
        for line in f:
            if "ml_prediction" in line:
                ml_count += 1
    print(f"   {YELLOW}🧠 ML Predictions Logged{RESET}  {WHITE}{BOLD}{ml_count}{RESET}")
    print(f"   {YELLOW}🕒 Last Modified{RESET}          {get_file_mtime(ml_log_file)}")

# ── Quick Stats ──────────────────────────────────────────────────────
print()
sep()
total = len(inv) + len(comp) + len(phi_remote) + len(forensic)
print(f"\n   {BOLD}{WHITE}📈 QUICK STATS{RESET}\n")
print(f"      {CYAN}🔍 Investigation Reports{RESET}      {BOLD}{len(inv):>4}{RESET}")
print(f"      {GREEN}📜 Compliance Reports{RESET}         {BOLD}{len(comp):>4}{RESET}")
print(f"      {ORANGE}🔒 PCAP PHI/Credential{RESET}        {BOLD}{len(phi_remote):>4}{RESET}")
print(f"      {PURPLE}🔬 Forensic Analysis{RESET}          {BOLD}{len(forensic):>4}{RESET}")
print(f"      {RED}📊 Total Reports{RESET}              {BOLD}{WHITE}{total:>4}{RESET}")
print()
sep()
print(f"\n   {GREEN}{BOLD}✏️  Healthcare IoMT EDR Platform · Kainat Zahra Khalil{RESET}")
print(f"{DIM}      EduQual Level 6 Diploma in AI Operations{RESET}\n")
