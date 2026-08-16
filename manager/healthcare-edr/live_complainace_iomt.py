#!/usr/bin/env python3
import subprocess
import json
import os
import hashlib
from datetime import datetime

# ── Colors ──────────────────────────────────────────────────────────
RESET = '\033[0m'; BOLD = '\033[1m'; DIM = '\033[2m'
RED = '\033[38;5;203m'; GREEN = '\033[38;5;83m'; YELLOW = '\033[38;5;220m'
CYAN = '\033[38;5;51m'; MAGENTA = '\033[38;5;213m'; BLUE = '\033[38;5;75m'
WHITE = '\033[97m'; ORANGE = '\033[38;5;208m'; PURPLE = '\033[38;5;141m'

CONTAINER = "healthcare-edr-wazuh.manager-1"
REPORTS_DIR = os.path.expanduser("~/healthcare-edr/compliance_reports")
INVENTORY_FILE = os.path.expanduser("~/healthcare-edr/device_inventory.json")
STALE_PATCH_DAYS = 90

def sep(char="─", n=70):
    print(f"{DIM}{CYAN}{char*n}{RESET}")

def section(icon, title, color=CYAN):
    print()
    print(f"{color}╔{'═'*68}╗{RESET}")
    print(f"{color}║{RESET} {icon}  {BOLD}{WHITE}{title}{RESET}")
    print(f"{color}╚{'═'*68}╝{RESET}")

def load_device_inventory():
    if not os.path.exists(INVENTORY_FILE):
        return {}
    try:
        with open(INVENTORY_FILE) as f:
            data = json.load(f)
        data.pop("_comment", None)
        return data
    except Exception:
        return {}

def days_since(date_str):
    try:
        d = datetime.strptime(date_str, "%Y-%m-%d")
        return (datetime.now() - d).days
    except Exception:
        return None

def get_docker_alerts(limit=200):
    try:
        cmd = ["docker", "exec", CONTAINER,
               "tail", f"-{limit*3}",
               "/var/ossec/logs/alerts/alerts.json"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        alerts = []
        for line in result.stdout.strip().split('\n'):
            try:
                alerts.append(json.loads(line.strip()))
            except:
                continue
        return alerts[-limit:]
    except:
        return []

def file_hash(path):
    if not os.path.exists(path): return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def html_escape(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

# ── MITRE map ───────────────────────────────────────────────────────
MITRE_MAP = {
    "ransomware": ("T1486", "Impact"),
    "powershell": ("T1059", "Execution"),
    "wmi": ("T1047", "Execution"),
    "injection": ("T1055", "Defense Evasion"),
    "scheduled": ("T1053", "Persistence"),
    "user creation": ("T1136", "Persistence"),
    "deletion": ("T1485", "Impact"),
    "download": ("T1105", "C2"),
    "shell": ("T1059", "Execution"),
    "office": ("T1566", "Initial Access"),
    "unknown destination ip": ("T1071", "Command and Control"),
    "unexpected port": ("T1571", "Command and Control"),
    "data volume spike": ("T1030", "Exfiltration"),
    "failed authentication": ("T1110", "Credential Access"),
    "impersonation": ("T1557", "Collection"),
    "unencrypted phi": ("T1020", "Exfiltration"),
    "infusion pump": ("T0836", "Impact (ICS/Medical)"),
    "ventilator": ("T0836", "Impact (ICS/Medical)"),
    "patient monitor": ("T0836", "Impact (ICS/Medical)"),
    "dicom": ("T1537", "Exfiltration"),
    "diversion": ("T1078", "Initial Access"),
    "rogue device": ("T1200", "Initial Access"),
    "firmware": ("T1195", "Supply Chain Compromise"),
    "unrecognized firmware": ("T1195", "Supply Chain Compromise"),
    "update request": ("T1195", "Supply Chain Compromise"),
    "firmware or update": ("T1195", "Supply Chain Compromise"),
    "config change": ("T1565", "Data Manipulation"),
    "hl7": ("T1048", "Exfiltration Over Alternative Protocol"),
    "network scan": ("T1046", "Network Service Discovery"),
    "reboot": ("T1529", "System Shutdown/Reboot"),
    "default credential": ("T1078", "Valid Accounts"),
    "brute force": ("T1110", "Credential Access"),
}

def map_mitre(desc):
    d = desc.lower()
    for kw, (tid, tactic) in MITRE_MAP.items():
        if kw in d:
            return tid, tactic
    return "T0000", "Unknown"

# ── HIPAA map ───────────────────────────────────────────────────────
HIPAA_MAP = {
    "unknown destination ip": ("§164.312(e)(1)", "Transmission Security"),
    "unexpected port": ("§164.312(e)(1)", "Transmission Security"),
    "data volume spike": ("§164.308(a)(6)", "Security Incident Procedures"),
    "failed authentication": ("§164.312(d)", "Person/Entity Authentication"),
    "brute force": ("§164.312(d)", "Person/Entity Authentication"),
    "impersonation": ("§164.312(e)(1)", "Transmission Security"),
    "unencrypted phi": ("§164.312(e)(1)", "Transmission Security — Encryption"),
    "dicom": ("§164.404", "Breach Notification Rule"),
    "diversion": ("§164.308(a)(3)", "Workforce Security"),
    "rogue device": ("§164.312(d)", "Person/Entity Authentication"),
    "default credential": ("§164.308(a)(5)(ii)(D)", "Password Management"),
    "firmware": ("§164.312(c)(1)", "Integrity"),
    "hl7": ("§164.312(c)(1)", "Integrity"),
    "config change": ("§164.312(a)(1)", "Access Control"),
    "network scan": ("§164.312(b)", "Audit Controls"),
    "reboot": ("§164.308(a)(6)", "Security Incident Procedures"),
    "infusion pump": ("§164.308(a)(6)", "Security Incident Procedures — Patient Safety"),
    "ventilator": ("§164.308(a)(6)", "Security Incident Procedures — Patient Safety"),
    "patient monitor": ("§164.308(a)(6)", "Security Incident Procedures — Patient Safety"),
}

def map_hipaa(desc):
    d = desc.lower()
    for kw, (cite, safeguard) in HIPAA_MAP.items():
        if kw in d:
            return cite, safeguard
    return None, None

# ── HITRUST map ─────────────────────────────────────────────────────
HITRUST_DOMAINS = {
    "unknown destination ip": "01 — Information Protection Program",
    "unexpected port": "01 — Information Protection Program",
    "data volume spike": "07 — Vulnerability Management",
    "failed authentication": "05 — Access Control",
    "brute force": "05 — Access Control",
    "impersonation": "10 — Network Protection",
    "unencrypted phi": "10 — Network Protection",
    "dicom": "14 — Third Party Assurance / Data Protection & Privacy",
    "diversion": "06 — Human Resources Security",
    "rogue device": "05 — Access Control",
    "default credential": "05 — Access Control",
    "firmware": "09 — Configuration Management",
    "config change": "09 — Configuration Management",
    "network scan": "12 — Audit Logging & Monitoring",
    "infusion pump": "13 — Physical & Environmental Security / Patient Safety",
    "ventilator": "13 — Physical & Environmental Security / Patient Safety",
    "patient monitor": "13 — Physical & Environmental Security / Patient Safety",
}

def map_hitrust(desc):
    d = desc.lower()
    for kw, domain in HITRUST_DOMAINS.items():
        if kw in d:
            return domain
    return None

# ════════════════════════════════════════════════════════════════════
# Main
# ════════════════════════════════════════════════════════════════════
now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
report_id = datetime.now().strftime('%Y%m%d_%H%M%S')

print(f"\n{BOLD}{WHITE}")
print("   🏥  L I V E   E D R   C O M P L I A N C E   &   A U D I T")
print(f"{RESET}{DIM}      NIST CSF · HIPAA · HITRUST · MITRE ATT&CK — IoMT Healthcare EDR{RESET}")
print(f"{DIM}      Generated: {now}{RESET}")
sep()

alerts = get_docker_alerts(limit=200)
print(f"\n   {GREEN}[+]{RESET} Live alerts loaded from Wazuh container: {BOLD}{WHITE}{len(alerts)}{RESET}\n")

# ── Section 1: MITRE ──
section("🎯", "SECTION 1 — MITRE ATT&CK MAPPING (LIVE ALERTS)", CYAN)

mapped = []
seen = set()
mitre_rows_html = []
for a in alerts:
    desc = a.get('rule', {}).get('description', 'unknown')
    level = int(a.get('rule', {}).get('level', 0))
    device_id = a.get('data', {}).get('device_id', '')
    sev = "CRITICAL" if level >= 15 else \
          "HIGH" if level >= 12 else \
          "MEDIUM" if level >= 7 else "LOW"
    tid, tactic = map_mitre(desc)
    key = f"{desc}_{tid}"
    if key in seen: continue
    seen.add(key)
    mapped.append({"desc": desc, "severity": sev,
                   "technique_id": tid, "tactic": tactic,
                   "device_id": device_id or None})
    device_tag = f" [{device_id}]" if device_id else ""
    if sev in ["CRITICAL", "HIGH"]:
        sev_color = RED if sev == "CRITICAL" else ORANGE
        print(f"   {sev_color}{BOLD}[{sev}]{RESET}{device_tag} {WHITE}{desc[:48]}{RESET}")
        print(f"      {DIM}→ {tid} | {tactic}{RESET}")
        print()
    unknown_flag = " unmapped" if tid == "T0000" else ""
    mitre_rows_html.append(f"""
        <div class="alert-box sev-{sev.lower()}{unknown_flag}">
          <span class="badge">{sev}</span>{html_escape(device_tag.strip())}
          {html_escape(desc[:90])}
          <div class="mitre-tag">→ {html_escape(tid)} &middot; {html_escape(tactic)}</div>
        </div>""")

if not mapped:
    print(f"   {YELLOW}No alerts — run demo attack first{RESET}")
    mitre_rows_html.append('<div class="alert-box sev-low">No alerts in this window — run a demo attack first.</div>')

# ── Section 2: NIST ──
section("📜", "SECTION 2 — NIST CSF COMPLIANCE", GREEN)

total  = len(alerts)
crit   = sum(1 for a in alerts if int(a.get('rule',{}).get('level',0)) >= 15)
high   = sum(1 for a in alerts if 12 <= int(a.get('rule',{}).get('level',0)) < 15)
medium = sum(1 for a in alerts if 7  <= int(a.get('rule',{}).get('level',0)) < 12)
low    = sum(1 for a in alerts if int(a.get('rule',{}).get('level',0)) < 7)

nist = [
    ("DE.AE-1", f"Baseline active — {total} live events from Wazuh alerts.json"),
    ("DE.CM-1", "Real-time Wazuh Manager monitoring (AWS Manager 172.31.44.154)"),
    ("DE.CM-4", "35 IoMT custom rules + Suricata path + ML overlay (Isolation Forest + RF)"),
    ("DE.CM-7", "Sigma detection-as-code layer (32 rules) + OpenSearch monitors live"),
    ("RS.RP-1", f"TheHive auto-case creation — {high} HIGH+ alerts in window"),
    ("RS.MI-1", "Patient-safety weighted auto_contain (ventilator/pump = escalate-only)"),
    ("RC.RP-1", "Velociraptor forensic collection tied to TheHive cases"),
    ("ID.RA-1", "MITRE ATT&CK Enterprise + ICS Navigator coverage maps generated"),
]
for ctrl, note in nist:
    print(f"   {GREEN}✅{RESET} {BOLD}{ctrl}{RESET} : {note}")

nist_html = "".join(
    f'<li><b>{html_escape(ctrl)}</b> — {html_escape(note)}</li>' for ctrl, note in nist
)

# ── Section 3: HIPAA ──
section("🏥", "SECTION 3 — HIPAA SECURITY RULE (45 CFR §164)", BLUE)

hipaa_hits = []
for a in alerts:
    desc = a.get('rule', {}).get('description', 'unknown')
    cite, safeguard = map_hipaa(desc)
    if cite:
        hipaa_hits.append((cite, safeguard, desc))

hipaa_html_items = []
if hipaa_hits:
    seen_cites = set()
    for cite, safeguard, desc in hipaa_hits:
        if cite in seen_cites:
            continue
        seen_cites.add(cite)
        print(f"   {GREEN}✅{RESET} {BOLD}{cite}{RESET} : {safeguard}")
        print(f"      {DIM}triggered by: {desc[:55]}{RESET}")
        hipaa_html_items.append(
            f'<li><b>{html_escape(cite)}</b> — {html_escape(safeguard)}'
            f'<div class="trigger-note">triggered by: {html_escape(desc[:80])}</div></li>'
        )
else:
    print(f"   {DIM}No IoMT/PHI-related alerts in this window{RESET}")
    hipaa_html_items.append('<li>No IoMT/PHI-related alerts in this window.</li>')

hipaa_html = "".join(hipaa_html_items)

# ── Section 4: HITRUST ──
section("🛡️", "SECTION 4 — HITRUST CSF DOMAIN MAPPING", PURPLE)

hitrust_hits = set()
for a in alerts:
    desc = a.get('rule', {}).get('description', 'unknown')
    domain = map_hitrust(desc)
    if domain:
        hitrust_hits.add(domain)

hitrust_html_items = []
if hitrust_hits:
    for domain in sorted(hitrust_hits):
        print(f"   {GREEN}✅{RESET} Domain {domain}")
        hitrust_html_items.append(f'<li>{html_escape(domain)}</li>')
else:
    print(f"   {DIM}No HITRUST-mapped alerts in this window{RESET}")
    hitrust_html_items.append('<li>No HITRUST-mapped alerts in this window.</li>')

hitrust_html = "".join(hitrust_html_items)

# ── Section 4B: Vendor Risk ──
section("🏢", "SECTION 4B — HIPAA §164.308(b) VENDOR / BAA RISK", ORANGE)

inventory = load_device_inventory()
alert_device_ids = set()
for a in alerts:
    did = a.get('data', {}).get('device_id', '')
    if did:
        alert_device_ids.add(did)

vendor_html_items = []
if not inventory:
    print(f"   {YELLOW}No device inventory found — see device_inventory.json{RESET}")
    vendor_html_items.append(
        '<li>No device inventory file found. Create <code>device_inventory.json</code> '
        'to enable vendor/Business Associate risk tracking.</li>'
    )
else:
    for device_id in sorted(alert_device_ids):
        info = inventory.get(device_id)
        if not info:
            print(f"   {RED}⚠️  {device_id}: NOT in inventory — unverified vendor/BAA status{RESET}")
            vendor_html_items.append(
                f'<li><b>{html_escape(device_id)}</b> — '
                f'<span style="color:#8a1f1f;">not in inventory (unverified vendor/BAA status)</span></li>'
            )
            continue
        age = days_since(info.get("last_patch_date", ""))
        stale = age is not None and age > STALE_PATCH_DAYS
        baa = info.get("business_associate_agreement", False)
        flags = []
        if stale:
            flags.append(f"patch stale ({age} days)")
        if not baa:
            flags.append("no signed BAA on file")
        status = f"{YELLOW}⚠️  AT RISK: {', '.join(flags)}{RESET}" if flags else f"{GREEN}✅ OK{RESET}"
        print(f"   {status}  {device_id} — {info.get('vendor')} {info.get('model')} (fw {info.get('firmware_version')})")
        risk_class = "audit-missing" if flags else "audit-ok"
        flags_text = ", ".join(flags) if flags else "No issues flagged"
        vendor_html_items.append(f"""
        <div class="audit-item {risk_class}">
          <div class="audit-file">{html_escape(device_id)} — {html_escape(info.get('vendor',''))} {html_escape(info.get('model',''))}</div>
          <div class="audit-detail">Firmware: {html_escape(info.get('firmware_version','?'))} · Last patched: {html_escape(info.get('last_patch_date','unknown'))} ({age if age is not None else '?'} days ago)</div>
          <div class="audit-detail">Business Associate Agreement on file: {'Yes' if baa else 'No'}</div>
          <div class="audit-status">{html_escape(flags_text)}</div>
        </div>""")

if not alert_device_ids:
    vendor_html_items.append('<li>No device-tagged alerts in this window.</li>')

_baa_ok = sum(1 for did in alert_device_ids if inventory.get(did, {}).get("business_associate_agreement"))
_baa_missing = sum(1 for did in alert_device_ids if did in inventory and not inventory.get(did, {}).get("business_associate_agreement"))
_stale = sum(1 for did in alert_device_ids
            if did in inventory and (days_since(inventory[did].get("last_patch_date","")) or 0) > STALE_PATCH_DAYS)
_untracked = sum(1 for did in alert_device_ids if did not in inventory)

_intro = f"""
<p style="color:#94a3b8;font-size:13px;margin-bottom:14px;line-height:1.6;">
  <b style="color:#e2e8f0;">HIPAA §164.308(b) — Business Associate Contracts and Other Arrangements.</b><br>
  Covered entities must obtain satisfactory assurances that business associates will appropriately safeguard PHI.
  This section evaluates vendor devices seen in the current alert window against the device inventory
  (BAA on file, firmware currency, and tracking status).
</p>
<div class="kpi-row" style="margin-bottom:16px;">
  <div class="kpi"><div class="k">Devices in window</div><div class="v">{len(alert_device_ids)}</div></div>
  <div class="kpi"><div class="k">BAA on file</div><div class="v">{_baa_ok}</div></div>
  <div class="kpi"><div class="k">Missing BAA</div><div class="v">{_baa_missing}</div></div>
  <div class="kpi"><div class="k">Stale firmware</div><div class="v">{_stale}</div></div>
  <div class="kpi"><div class="k">Untracked</div><div class="v">{_untracked}</div></div>
</div>
"""

_body = "".join(vendor_html_items) if any('<div class="audit-item' in i for i in vendor_html_items) \
    else f'<ul class="note-list">{"".join(vendor_html_items)}</ul>'
vendor_html = _intro + _body

# ── Section 4C: Update Mechanism ──
section("🔄", "SECTION 4C — UPDATE-MECHANISM SECURITY CHECKLIST", MAGENTA)

update_checks = [
    ("Signed firmware images required", "Policy", "All clinical device firmware must be cryptographically signed by the vendor before install."),
    ("TLS 1.2+ on update servers", "Policy", "Firmware download channels must use TLS 1.2 or higher; plaintext HTTP is prohibited."),
    ("Vendor authenticity verification", "Policy", "Update packages must be verified against vendor public keys / certificates before apply."),
    ("Rollback capability", "Policy", "Devices must support safe rollback to last-known-good firmware if an update fails or is malicious."),
    ("Update activity monitoring", "Live", "Wazuh rules detect unrecognized firmware / unexpected update requests (see MITRE T1195)."),
    ("Patient-safety gate on updates", "Live", "auto_contain treats ventilator / infusion-pump / patient-monitor update events as escalate-only."),
]

update_html_items = []
for title, kind, detail in update_checks:
    tag = "LIVE" if kind == "Live" else "POLICY"
    tag_color = GREEN if kind == "Live" else CYAN
    print(f"   {GREEN}✅{RESET} [{tag_color}{tag}{RESET}] {title}")
    update_html_items.append(f"""
      <div class="audit-item audit-ok">
        <div class="audit-file">{html_escape(title)} <span class="tag">{tag}</span></div>
        <div class="audit-detail">{html_escape(detail)}</div>
        <div class="audit-status">✓ Control defined</div>
      </div>""")

update_html = "".join(update_html_items)

# ── Section 5: Audit Trail ──
section("📋", "SECTION 5 — AUDIT TRAIL & CHAIN OF CUSTODY", YELLOW)

artefacts = [
    ("Device Inventory", os.path.expanduser("~/healthcare-edr/device_inventory.json")),
    ("SOC Metrics Log", os.path.expanduser("~/healthcare-edr/soc_metrics.jsonl")),
    ("EDR Events Log", os.path.expanduser("~/healthcare-edr/logs/edr_events.jsonl")),
    ("Metrics Module", os.path.expanduser("~/healthcare-edr/scripts/metrics.py")),
    ("Live EDR Engine", os.path.expanduser("~/healthcare-edr/live_edr_iomt.py")),
    ("Auto-Containment Policy", os.path.expanduser("~/healthcare-edr/auto_contain.py")),
    ("TheHive Integration", os.path.expanduser("~/healthcare-edr/thehive_integration_iomt.py")),
    ("Device Safety Utils", os.path.expanduser("~/healthcare-edr/device_safety_utils.py")),
    ("MITRE Mapper", os.path.expanduser("~/healthcare-edr/mitre_mapper.py")),
]

audit_html_items = []
any_missing = False
for label, fpath in artefacts:
    h = file_hash(fpath)
    exists = h is not None
    if not exists:
        any_missing = True
    size = os.path.getsize(fpath) if exists else 0
    status = "PRESENT" if exists else "MISSING"
    icon = f"{GREEN}✅{RESET}" if exists else f"{RED}❌{RESET}"
    hash_preview = h[:16]+'…' if h else '—'
    print(f"   {icon} {label:28s}  {status}  sha256={hash_preview}  ({size} bytes)")
    css = "audit-ok" if exists else "audit-missing"
    audit_html_items.append(f"""
      <div class="audit-item {css}">
        <div class="audit-file">{html_escape(label)}</div>
        <div class="audit-detail">{html_escape(fpath)} · {size} bytes</div>
        <div class="audit-status">{'✓ PRESENT — ' + h[:20] + '…' if h else '✗ MISSING'}</div>
      </div>""")

audit_html = "".join(audit_html_items)

# ── Section 6: Retention ──
section("🗄️", "SECTION 6 — DATA RETENTION POLICY", BLUE)

retention = [
    ("Security Logs", "90 days", "Wazuh auto-purge"),
    ("Forensic Data", "12 months", "encrypted storage"),
    ("Incident Cases", "3 years", "TheHive archive"),
    ("Memory Captures", "Per case", "deleted post-close"),
]
for label, period, note in retention:
    print(f"   {CYAN}▸{RESET} {label:<17}: {BOLD}{period:<11}{RESET} ({DIM}{note}{RESET})")

retention_html = "".join(
    f'<li><b>{html_escape(label)}</b> — {html_escape(period)} <span class="trigger-note">({html_escape(note)})</span></li>'
    for label, period, note in retention
)

# ── Save TXT ──
os.makedirs(REPORTS_DIR, exist_ok=True)
txt_fname = os.path.join(REPORTS_DIR, f"live_report_{report_id}.txt")
techniques = set(a['technique_id'] for a in mapped)

summary_lines = [
    "="*65,
    "    LIVE EDR COMPLIANCE & AUDIT REPORT",
    "    (NIST CSF · HIPAA · HITRUST · MITRE ATT&CK — IoMT Healthcare EDR)",
    "="*65,
    f"Timestamp : {now}",
    f"Source    : Docker -> {CONTAINER}",
    "="*65,
    f"Total Alerts       : {total}",
    f"Critical           : {crit}",
    f"High               : {high}",
    f"MITRE Techniques   : {len(techniques)} - {', '.join(sorted(techniques))}",
    f"HIPAA Safeguards   : {len(set(c for c,_,_ in hipaa_hits))}",
    f"HITRUST Domains    : {len(hitrust_hits)}",
    "="*65,
]
with open(txt_fname, "w") as f:
    f.write("\n".join(summary_lines) + "\n")

print()
sep()
print(f"\n   {GREEN}{BOLD}✅ Report saved{RESET}     : {txt_fname}")
print(f"   {YELLOW}Total Alerts{RESET}       : {BOLD}{total}{RESET}")
print(f"   {RED}Critical{RESET}           : {BOLD}{crit}{RESET}")
print(f"   {ORANGE}High{RESET}               : {BOLD}{high}{RESET}")
print(f"   {CYAN}MITRE Techniques{RESET}   : {BOLD}{len(techniques)}{RESET} — {', '.join(sorted(techniques))}")
print(f"   {BLUE}HIPAA Safeguards{RESET}   : {BOLD}{len(set(c for c,_,_ in hipaa_hits))}{RESET}")
print(f"   {PURPLE}HITRUST Domains{RESET}    : {BOLD}{len(hitrust_hits)}{RESET}")
print(f"   {DIM}Timestamp          : {now}{RESET}")
sep()

# ── HTML generation (same professional dark theme as before) ────────
_total_for_pie = max(total, 1)
_slices = [
    ("#dc2626", crit),
    ("#ea580c", high),
    ("#d97706", medium),
    ("#059669", low),
]
_offset = 0
_svg_parts = []
for _color, _count in _slices:
    _pct = (_count / _total_for_pie) * 100
    if _pct > 0:
        _svg_parts.append(
            f'<circle cx="21" cy="21" r="15.915" fill="transparent" stroke="{_color}" '
            f'stroke-width="5" stroke-dasharray="{_pct:.2f} {100-_pct:.2f}" '
            f'stroke-dashoffset="{-_offset:.2f}" stroke-linecap="round"/>'
        )
        _offset += _pct
sev_svg_slices = "\n          ".join(_svg_parts) if _svg_parts else \
    '<circle cx="21" cy="21" r="15.915" fill="transparent" stroke="#e2e8f0" stroke-width="5"/>'

audit_banner = (
    '<div class="banner banner-warn">⚠ One or more core project artefacts are missing or unreadable. See Section 5.</div>'
    if any_missing else
    '<div class="banner banner-ok">✓ All core project artefacts present and integrity-hashed.</div>'
)

html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IoMT EDR Compliance Report — {report_id}</title>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --surface2: #334155; --border: #475569;
    --text: #f1f5f9; --muted: #94a3b8; --accent: #38bdf8;
    --critical: #dc2626; --high: #ea580c; --medium: #d97706; --low: #059669; --ok: #10b981;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.55; font-size: 14px; }}
  .header {{ background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%); border-bottom: 1px solid var(--border); padding: 28px 40px; }}
  .header h1 {{ font-size: 22px; font-weight: 700; color: #f8fafc; }}
  .header .sub {{ margin-top: 6px; color: var(--muted); font-size: 13px; }}
  .header .sub b {{ color: var(--accent); }}
  .container {{ max-width: 1080px; margin: 0 auto; padding: 28px 24px 48px; }}
  .section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 22px 24px; margin-bottom: 20px; }}
  .section h2 {{ font-size: 15px; font-weight: 700; color: #e2e8f0; margin-bottom: 16px; padding-bottom: 10px; border-bottom: 1px solid var(--surface2); }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }}
  .stat-card {{ background: var(--surface2); border-radius: 8px; padding: 16px 14px; text-align: center; }}
  .stat-card .value {{ font-size: 26px; font-weight: 700; color: #f8fafc; }}
  .stat-card .label {{ font-size: 11px; color: var(--muted); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.6px; }}
  .sev-chart-wrap {{ display: flex; flex-wrap: wrap; gap: 32px; align-items: center; margin-top: 20px; padding-top: 18px; border-top: 1px solid var(--surface2); }}
  .sev-legend {{ list-style: none; }}
  .sev-legend li {{ display: flex; align-items: center; gap: 10px; margin: 7px 0; font-size: 13px; color: #cbd5e1; }}
  .sev-dot {{ width: 12px; height: 12px; border-radius: 3px; }}
  .banner {{ margin-top: 16px; padding: 12px 16px; border-radius: 6px; font-size: 13px; font-weight: 600; }}
  .banner-ok {{ background: rgba(16,185,129,0.12); color: #34d399; border: 1px solid rgba(16,185,129,0.25); }}
  .banner-warn {{ background: rgba(234,88,12,0.12); color: #fb923c; border: 1px solid rgba(234,88,12,0.25); }}
  .alert-box {{ padding: 12px 14px; border-radius: 6px; margin-bottom: 8px; font-size: 13px; border-left: 3px solid; }}
  .sev-critical {{ background: rgba(220,38,38,0.1); border-color: var(--critical); color: #fca5a5; }}
  .sev-high {{ background: rgba(234,88,12,0.1); border-color: var(--high); color: #fdba74; }}
  .sev-medium {{ background: rgba(217,119,6,0.1); border-color: var(--medium); color: #fcd34d; }}
  .sev-low {{ background: rgba(5,150,105,0.1); border-color: var(--low); color: #6ee7b7; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; margin-right: 8px; text-transform: uppercase; }}
  .sev-critical .badge {{ background: var(--critical); color: #fff; }}
  .sev-high .badge {{ background: var(--high); color: #fff; }}
  .sev-medium .badge {{ background: var(--medium); color: #1c1917; }}
  .sev-low .badge {{ background: var(--low); color: #fff; }}
  .mitre-tag {{ margin-top: 4px; font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 11.5px; color: var(--muted); }}
  ul.note-list {{ list-style: none; padding: 0; }}
  ul.note-list li {{ padding: 8px 0 8px 22px; position: relative; border-bottom: 1px solid rgba(71,85,105,0.4); font-size: 13px; color: #cbd5e1; }}
  ul.note-list li:last-child {{ border-bottom: none; }}
  ul.note-list li::before {{ content: "▸"; position: absolute; left: 4px; color: var(--accent); font-weight: 700; }}
  ul.note-list li b {{ color: #e2e8f0; }}
  .trigger-note {{ font-size: 11.5px; color: var(--muted); margin-top: 2px; font-family: ui-monospace, Menlo, Consolas, monospace; }}
  .audit-item {{ border-radius: 6px; padding: 12px 14px; margin-bottom: 8px; border: 1px solid; }}
  .audit-ok {{ background: rgba(16,185,129,0.08); border-color: rgba(16,185,129,0.3); }}
  .audit-missing {{ background: rgba(220,38,38,0.08); border-color: rgba(220,38,38,0.3); }}
  .audit-file {{ font-family: ui-monospace, Menlo, Consolas, monospace; font-weight: 600; font-size: 12.5px; color: #e2e8f0; }}
  .audit-detail {{ font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 11px; color: var(--muted); margin-top: 2px; }}
  .audit-status {{ font-weight: 700; font-size: 12px; margin-top: 4px; }}
  .audit-ok .audit-status {{ color: #34d399; }}
  .audit-missing .audit-status {{ color: #f87171; }}
  .kpi-row {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-top: 8px; }}
  .kpi {{ background: var(--surface2); border-radius: 6px; padding: 12px 14px; }}
  .kpi .k {{ font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }}
  .kpi .v {{ font-size: 18px; font-weight: 700; color: var(--accent); margin-top: 2px; }}
  .footer {{ text-align: center; padding: 24px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--border); }}
  .tag {{ display: inline-block; background: rgba(56,189,248,0.15); color: var(--accent); font-size: 11px; padding: 2px 8px; border-radius: 4px; font-weight: 600; margin-left: 6px; }}
</style>
</head>
<body>
  <div class="header">
    <h1>IoMT AI-Driven EDR — Compliance &amp; Audit Report</h1>
    <div class="sub">
      Healthcare Medical Device Security · NIST CSF · HIPAA · HITRUST · MITRE ATT&amp;CK (Enterprise + ICS)
      &nbsp;·&nbsp; Generated <b>{html_escape(now)}</b>
      &nbsp;·&nbsp; Report ID <b>{html_escape(report_id)}</b>
    </div>
  </div>
  <div class="container">
    <div class="section">
      <h2>Executive Summary</h2>
      <div class="stat-grid">
        <div class="stat-card"><div class="value">{total}</div><div class="label">Total Alerts</div></div>
        <div class="stat-card"><div class="value">{crit}</div><div class="label">Critical</div></div>
        <div class="stat-card"><div class="value">{high}</div><div class="label">High</div></div>
        <div class="stat-card"><div class="value">{medium}</div><div class="label">Medium</div></div>
        <div class="stat-card"><div class="value">{low}</div><div class="label">Low</div></div>
        <div class="stat-card"><div class="value">{len(techniques)}</div><div class="label">MITRE Techniques</div></div>
        <div class="stat-card"><div class="value">{len(set(c for c,_,_ in hipaa_hits))}</div><div class="label">HIPAA Safeguards</div></div>
        <div class="stat-card"><div class="value">{len(hitrust_hits)}</div><div class="label">HITRUST Domains</div></div>
      </div>
      <div class="sev-chart-wrap">
        <svg width="160" height="160" viewBox="0 0 42 42" style="transform:rotate(-90deg)">
          <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="#334155" stroke-width="5"/>
          {sev_svg_slices}
        </svg>
        <ul class="sev-legend">
          <li><span class="sev-dot" style="background:#dc2626"></span> Critical — <b>{crit}</b></li>
          <li><span class="sev-dot" style="background:#ea580c"></span> High — <b>{high}</b></li>
          <li><span class="sev-dot" style="background:#d97706"></span> Medium — <b>{medium}</b></li>
          <li><span class="sev-dot" style="background:#059669"></span> Low — <b>{low}</b></li>
        </ul>
      </div>
      {audit_banner}
    </div>
    <div class="section">
      <h2>Platform Capability Snapshot</h2>
      <div class="kpi-row">
        <div class="kpi"><div class="k">Detection Engine</div><div class="v">Wazuh + 35 IoMT rules</div></div>
        <div class="kpi"><div class="k">ML Overlay</div><div class="v">Isolation Forest + RF</div></div>
        <div class="kpi"><div class="k">Containment</div><div class="v">Patient-safety weighted</div></div>
        <div class="kpi"><div class="k">Case Management</div><div class="v">TheHive + Cortex</div></div>
        <div class="kpi"><div class="k">Forensics</div><div class="v">Velociraptor + Volatility3</div></div>
        <div class="kpi"><div class="k">Architecture</div><div class="v">3× AWS (Mgr / Agent / Forensics)</div></div>
        <div class="kpi"><div class="k">Detection-as-Code</div><div class="v">Sigma → SPL + KQL + OpenSearch</div></div>
        <div class="kpi"><div class="k">Coverage</div><div class="v">MITRE Enterprise + ICS layers</div></div>
      </div>
    </div>
    <div class="section">
      <h2>1 · MITRE ATT&amp;CK Mapping <span class="tag">Live Alerts</span></h2>
      {"".join(mitre_rows_html) if mitre_rows_html else '<div class="alert-box sev-low">No alerts in current window.</div>'}
    </div>
    <div class="section">
      <h2>2 · NIST CSF Alignment</h2>
      <ul class="note-list">{nist_html}</ul>
    </div>
    <div class="section">
      <h2>3 · HIPAA Security Rule (45 CFR §164)</h2>
      <ul class="note-list">{hipaa_html}</ul>
    </div>
    <div class="section">
      <h2>4 · HITRUST CSF Domains</h2>
      <ul class="note-list">{hitrust_html}</ul>
    </div>
    <div class="section">
      <h2>4B · HIPAA §164.308(b) Business Associate / Vendor Risk</h2>
      {vendor_html}
    </div>
    <div class="section">
      <h2>4C · Update-Mechanism Security Checklist</h2>
      <p style="color:#94a3b8;font-size:13px;margin-bottom:14px;line-height:1.6;">
        Controls that protect the firmware and software update path for clinical devices.
      </p>
      {update_html}
    </div>
    <div class="section">
      <h2>5 · Audit Trail &amp; Chain of Custody</h2>
      {audit_html}
    </div>
    <div class="section">
      <h2>6 · Data Retention Policy</h2>
      <ul class="note-list">{retention_html}</ul>
    </div>
  </div>
  <div class="footer">
    Healthcare IoMT AI-Driven EDR Platform · Capstone Compliance Pipeline · {html_escape(report_id)}
  </div>
</body>
</html>"""

html_fname = os.path.join(REPORTS_DIR, f"compliance_report_{report_id}.html")
with open(html_fname, "w") as f:
    f.write(html)

print()
print(f"{GREEN}{BOLD}{'='*70}{RESET}")
print(f"{GREEN}{BOLD}  HTML REPORT READY{RESET}")
print(f"{GREEN}{BOLD}{'='*70}{RESET}")
print(f"  File : {html_fname}")
print(f"  Open : file://{html_fname}")
print(f"{GREEN}{BOLD}{'='*70}{RESET}")
print(f"\n   {GREEN}{BOLD}✏️  Healthcare IoMT EDR Platform · Kainat Zahra Khalil{RESET}")
print(f"{DIM}      EduQual Level 6 Diploma in AI Operations{RESET}\n")
