#!/usr/bin/env python3
import sys
from pathlib import Path
from datetime import datetime

RESET = '\033[0m'; BOLD = '\033[1m'; DIM = '\033[2m'
RED = '\033[38;5;203m'; GREEN = '\033[38;5;83m'; YELLOW = '\033[38;5;220m'
CYAN = '\033[38;5;51m'; MAGENTA = '\033[38;5;213m'; BLUE = '\033[38;5;75m'
WHITE = '\033[97m'; ORANGE = '\033[38;5;208m'; PURPLE = '\033[38;5;141m'

def sep():
    print(f"{DIM}{CYAN}{'─'*78}{RESET}")

def section(icon, title, color):
    print()
    print(f"{color}╔{'═'*76}╗{RESET}")
    print(f"{color}║{RESET} {icon}  {BOLD}{WHITE}{title}{RESET}")
    print(f"{color}╚{'═'*76}╝{RESET}")

# ── Find latest report ──────────────────────────────────────────────
report_dir = Path.home() / "pcap_reports"
reports = sorted(report_dir.glob("phi_credential_check_*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)

if not reports:
    print(f"{RED}No PHI/Credential reports found in ~/pcap_reports/{RESET}")
    sys.exit(1)

latest = reports[0]
content = latest.read_text()

# ── Parse key fields ────────────────────────────────────────────────
generated = file_path = size = http_req = risk = "N/A"
for line in content.splitlines():
    if line.startswith("Generated"):
        generated = line.split(":", 1)[1].strip()
    elif line.startswith("File"):
        file_path = line.split(":", 1)[1].strip()
    elif line.startswith("Size"):
        size = line.split(":", 1)[1].strip()
    elif line.startswith("HTTP Requests"):
        http_req = line.split(":", 1)[1].strip()
    elif line.startswith("Overall Risk"):
        risk = line.split(":", 1)[1].strip()

# ── Header ──────────────────────────────────────────────────────────
print(f"\n{BOLD}{WHITE}")
print("   🔒  P C A P   C L E A R T E X T   P H I   &   C R E D E N T I A L")
print(f"{RESET}{DIM}      Leak Check Report · Forensics Node{RESET}")
print(f"{DIM}      Generated: {generated}{RESET}")
sep()

# ── File Info ───────────────────────────────────────────────────────
section("📄", "SCAN TARGET", CYAN)
print(f"   {YELLOW}File{RESET}          {WHITE}{Path(file_path).name}{RESET}")
print(f"   {YELLOW}Full Path{RESET}     {DIM}{file_path}{RESET}")
print(f"   {YELLOW}Size{RESET}          {WHITE}{size}{RESET}")
print(f"   {YELLOW}HTTP Requests{RESET} {WHITE}{http_req}{RESET}")

# ── Risk ────────────────────────────────────────────────────────────
section("⚠️ ", "OVERALL RISK", ORANGE if risk == "LOW" else RED)
risk_color = GREEN if risk == "LOW" else (YELLOW if risk == "MEDIUM" else RED)
print(f"   {risk_color}{BOLD}●  {risk}{RESET}")

# ── Credentials ─────────────────────────────────────────────────────
section("🔑", "CLEARTEXT CREDENTIALS", MAGENTA)
if "No HTTP Basic Auth headers detected" in content:
    print(f"   {GREEN}✓{RESET}  No HTTP Basic Auth headers detected")
else:
    print(f"   {RED}✗{RESET}  HTTP Basic Auth headers FOUND")

if "No cleartext password fields detected" in content:
    print(f"   {GREEN}✓{RESET}  No cleartext password fields detected")
else:
    print(f"   {RED}✗{RESET}  Cleartext password fields FOUND")

# ── PHI ─────────────────────────────────────────────────────────────
section("🏥", "POTENTIAL PHI EXPOSURE", BLUE)
if "No strong PHI patterns" in content:
    print(f"   {GREEN}✓{RESET}  No strong PHI patterns (MRN / SSN / DOB) detected")
else:
    print(f"   {RED}✗{RESET}  Potential PHI patterns detected — review required")

# ── Notes ───────────────────────────────────────────────────────────
section("📌", "NOTES & RECOMMENDATIONS", PURPLE)
print(f"   {DIM}•{RESET} No cleartext credentials or strong PHI found in HTTP/data layers.")
print(f"   {DIM}•{RESET} Expected when demo traffic uses encrypted channels (TLS/SSH).")
print()
print(f"   {YELLOW}Recommendations:{RESET}")
print(f"   {GREEN}▸{RESET} Prefer TLS 1.2+ for all clinical device communications")
print(f"   {GREEN}▸{RESET} Disable HTTP Basic Auth on management interfaces")
print(f"   {GREEN}▸{RESET} Ensure DICOM / HL7 interfaces are encrypted or isolated")
print(f"   {GREEN}▸{RESET} Any confirmed PHI in cleartext = treat as HIPAA incident")

# ── Footer ──────────────────────────────────────────────────────────
print()
sep()
print(f"\n   {GREEN}{BOLD}✏️  Healthcare IoMT EDR Platform · Kainat Zahra Khalil{RESET}")
print(f"{DIM}      EduQual Level 6 Diploma in AI Operations{RESET}")
print(f"{DIM}      Report file: {latest.name}{RESET}\n")
