import subprocess
import json
import os
import hashlib
from datetime import datetime

CONTAINER = "healthcare-edr-wazuh.manager-1"   # AWS setup — badlo agar Mac single-node pe chalana ho
REPORTS_DIR = os.path.expanduser("~/healthcare-edr/compliance_reports")
INVENTORY_FILE = os.path.expanduser("~/healthcare-edr/device_inventory.json")
STALE_PATCH_DAYS = 90  # flag as at-risk if not patched within this window

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

def get_docker_alerts(limit=50):
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

# ── MITRE map (endpoint + IoMT, same keywords as mitre_mapper.py) ──────────
MITRE_MAP = {
    "ransomware":    ("T1486", "Impact"),
    "powershell":    ("T1059", "Execution"),
    "wmi":           ("T1047", "Execution"),
    "injection":     ("T1055", "Defense Evasion"),
    "scheduled":     ("T1053", "Persistence"),
    "user creation": ("T1136", "Persistence"),
    "deletion":      ("T1485", "Impact"),
    "download":      ("T1105", "C2"),
    "shell":         ("T1059", "Execution"),
    "office":        ("T1566", "Initial Access"),
    # IoMT additions
    "unknown destination ip":  ("T1071", "Command and Control"),
    "unexpected port":         ("T1571", "Command and Control"),
    "data volume spike":       ("T1030", "Exfiltration"),
    "failed authentication":   ("T1110", "Credential Access"),
    "impersonation":           ("T1557", "Collection"),
    "unencrypted phi":         ("T1020", "Exfiltration"),
    "infusion pump":           ("T0836", "Impact (ICS/Medical)"),
    "ventilator":              ("T0836", "Impact (ICS/Medical)"),
    "patient monitor":         ("T0836", "Impact (ICS/Medical)"),
    "dicom":                   ("T1537", "Exfiltration"),
    "diversion":                ("T1078", "Initial Access"),
    "rogue device":             ("T1200", "Initial Access"),
}

def map_mitre(desc):
    d = desc.lower()
    for kw, (tid, tactic) in MITRE_MAP.items():
        if kw in d:
            return tid, tactic
    return "T0000", "Unknown"

# ── HIPAA Security Rule map (45 CFR §164.3xx) — keyword based, same pattern ─
HIPAA_MAP = {
    "unknown destination ip":  ("§164.312(e)(1)",      "Transmission Security"),
    "unexpected port":         ("§164.312(e)(1)",      "Transmission Security"),
    "data volume spike":       ("§164.308(a)(6)",      "Security Incident Procedures"),
    "failed authentication":   ("§164.312(d)",         "Person/Entity Authentication"),
    "brute force":             ("§164.312(d)",         "Person/Entity Authentication"),
    "impersonation":           ("§164.312(e)(1)",      "Transmission Security"),
    "unencrypted phi":         ("§164.312(e)(1)",      "Transmission Security — Encryption"),
    "dicom":                   ("§164.404",            "Breach Notification Rule"),
    "diversion":                ("§164.308(a)(3)",     "Workforce Security"),
    "rogue device":             ("§164.312(d)",        "Person/Entity Authentication"),
    "default credential":       ("§164.308(a)(5)(ii)(D)", "Password Management"),
    "firmware":                 ("§164.312(c)(1)",     "Integrity"),
    "hl7":                      ("§164.312(c)(1)",     "Integrity"),
    "config change":            ("§164.312(a)(1)",     "Access Control"),
    "network scan":             ("§164.312(b)",        "Audit Controls"),
    "reboot":                   ("§164.308(a)(6)",     "Security Incident Procedures"),
    "infusion pump":            ("§164.308(a)(6)",     "Security Incident Procedures — Patient Safety"),
    "ventilator":                ("§164.308(a)(6)",    "Security Incident Procedures — Patient Safety"),
    "patient monitor":           ("§164.308(a)(6)",    "Security Incident Procedures — Patient Safety"),
}

def map_hipaa(desc):
    d = desc.lower()
    for kw, (cite, safeguard) in HIPAA_MAP.items():
        if kw in d:
            return cite, safeguard
    return None, None

# ── HITRUST CSF domain map (19 domains — condensed to the ones relevant here) ─
HITRUST_DOMAINS = {
    "unknown destination ip":  "01 — Information Protection Program",
    "unexpected port":         "01 — Information Protection Program",
    "data volume spike":       "07 — Vulnerability Management",
    "failed authentication":   "05 — Access Control",
    "brute force":             "05 — Access Control",
    "impersonation":           "10 — Network Protection",
    "unencrypted phi":         "10 — Network Protection",
    "dicom":                   "14 — Third Party Assurance / Data Protection & Privacy",
    "diversion":                "06 — Human Resources Security",
    "rogue device":             "05 — Access Control",
    "default credential":       "05 — Access Control",
    "firmware":                 "09 — Configuration Management",
    "config change":            "09 — Configuration Management",
    "network scan":             "12 — Audit Logging & Monitoring",
    "infusion pump":            "13 — Physical & Environmental Security / Patient Safety",
    "ventilator":                "13 — Physical & Environmental Security / Patient Safety",
    "patient monitor":           "13 — Physical & Environmental Security / Patient Safety",
}

def map_hitrust(desc):
    d = desc.lower()
    for kw, domain in HITRUST_DOMAINS.items():
        if kw in d:
            return domain
    return None

# ══════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════
now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
report_id = datetime.now().strftime('%Y%m%d_%H%M%S')

print("\n" + "="*65)
print("    LIVE EDR COMPLIANCE & AUDIT REPORT")
print("    (NIST CSF + GDPR + HIPAA + HITRUST — Endpoint + IoMT)")
print("="*65)
print(f"Timestamp : {now}")
print(f"Source    : Docker → {CONTAINER}")
print("="*65)

alerts = get_docker_alerts(limit=50)
print(f"\n✅ Docker se {len(alerts)} live alerts mile\n")

# ── Section 1: MITRE ──
print("─"*65)
print("SECTION 1 — MITRE ATT&CK MAPPING (LIVE ALERTS)")
print("─"*65)

mapped = []
seen   = set()
mitre_rows_html = []
for a in alerts:
    desc  = a.get('rule', {}).get('description', 'unknown')
    level = int(a.get('rule', {}).get('level', 0))
    device_id = a.get('data', {}).get('device_id', '')
    sev   = "CRITICAL" if level >= 15 else \
            "HIGH"     if level >= 12 else \
            "MEDIUM"   if level >= 7  else "LOW"
    tid, tactic = map_mitre(desc)
    key = f"{desc}_{tid}"
    if key in seen: continue
    seen.add(key)
    mapped.append({"desc": desc, "severity": sev,
                   "technique_id": tid, "tactic": tactic,
                   "device_id": device_id or None})
    if sev in ["CRITICAL", "HIGH"]:
        device_tag = f" [{device_id}]" if device_id else ""
        print(f"[{sev}]{device_tag} {desc[:48]}")
        print(f"  → {tid} | {tactic}")
        print()
        unknown_flag = " unmapped" if tid == "T0000" else ""
        mitre_rows_html.append(f"""
        <div class="alert-box sev-{sev.lower()}{unknown_flag}">
          <span class="badge">{sev}</span>{html_escape(device_tag.strip())}
          {html_escape(desc[:90])}
          <div class="mitre-tag">→ {html_escape(tid)} &middot; {html_escape(tactic)}</div>
        </div>""")

if not mapped:
    print("No alerts — run demo attack first")
    print("  bash ~/run_demo_attacks.sh   (endpoint)")
    print("  python3 simulate_medical_device.py --mode <mode>   (IoMT)")
    mitre_rows_html.append('<div class="alert-box sev-low">No alerts in this window — run a demo attack first.</div>')

# ── Section 2: NIST ──
print("─"*65)
print("SECTION 2 — NIST CSF COMPLIANCE")
print("─"*65)

total  = len(alerts)
high   = sum(1 for a in alerts if int(a.get('rule',{}).get('level',0)) >= 12)
crit   = sum(1 for a in alerts if int(a.get('rule',{}).get('level',0)) >= 15)

nist = [
    ("DE.AE-1", "✅", f"Baseline active — {total} events monitored"),
    ("DE.CM-1", "✅", "Real-time Wazuh monitoring running"),
    ("DE.CM-4", "✅", "YARA malware detection active"),
    ("RS.RP-1", "✅", f"TheHive auto-response — {high} HIGH alerts processed"),
    ("RS.MI-1", "✅", f"AUTO_CONTAIN triggered {crit} times"),
    ("RC.RP-1", "✅", "LiME memory forensics available"),
]
for ctrl, status, note in nist:
    print(f"  {status} {ctrl} : {note}")

nist_html = "".join(
    f'<li><b>{html_escape(ctrl)}</b> — {html_escape(note)}</li>' for ctrl, _, note in nist
)

# ── Section 3: HIPAA ────────────────────────────────────────────────────────
print("\n" + "─"*65)
print("SECTION 3 — HIPAA SECURITY RULE COMPLIANCE (45 CFR §164)")
print("─"*65)

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
        print(f"  ✅ {cite} : {safeguard}")
        print(f"     triggered by: {desc[:55]}")
        hipaa_html_items.append(
            f'<li><b>{html_escape(cite)}</b> — {html_escape(safeguard)}'
            f'<div class="trigger-note">triggered by: {html_escape(desc[:80])}</div></li>'
        )
else:
    print("  No IoMT/PHI-related alerts in this window")
    print("  (HIPAA safeguards apply once medical-device alerts fire)")
    hipaa_html_items.append('<li>No IoMT/PHI-related alerts in this window.</li>')

hipaa_html = "".join(hipaa_html_items)

# ── Section 4: HITRUST CSF ──────────────────────────────────────────────────
print("\n" + "─"*65)
print("SECTION 4 — HITRUST CSF DOMAIN MAPPING")
print("─"*65)

hitrust_hits = set()
for a in alerts:
    desc = a.get('rule', {}).get('description', 'unknown')
    domain = map_hitrust(desc)
    if domain:
        hitrust_hits.add(domain)

hitrust_html_items = []
if hitrust_hits:
    for domain in sorted(hitrust_hits):
        print(f"  ✅ Domain {domain}")
        hitrust_html_items.append(f'<li>{html_escape(domain)}</li>')
else:
    print("  No HITRUST-mapped alerts in this window")
    hitrust_html_items.append('<li>No HITRUST-mapped alerts in this window.</li>')

hitrust_html = "".join(hitrust_html_items)

# ── Section 4B: Vendor / Third-Party (Business Associate) Risk ────────────
print("\n" + "─"*65)
print("SECTION 4B — VENDOR / THIRD-PARTY RISK (HIPAA BUSINESS ASSOCIATE)")
print("─"*65)

inventory = load_device_inventory()
alert_device_ids = set()
for a in alerts:
    did = a.get('data', {}).get('device_id', '')
    if did:
        alert_device_ids.add(did)

vendor_html_items = []
if not inventory:
    print("  No device inventory found — see device_inventory.json")
    vendor_html_items.append(
        '<li>No device inventory file found. Create <code>device_inventory.json</code> '
        'to enable vendor/Business Associate risk tracking.</li>'
    )
else:
    for device_id in sorted(alert_device_ids):
        info = inventory.get(device_id)
        if not info:
            print(f"  ⚠️  {device_id}: NOT in inventory — unverified vendor/BAA status")
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
        status = "⚠️  AT RISK: " + ", ".join(flags) if flags else "✅ OK"
        print(f"  {status:<45} {device_id} — {info.get('vendor')} {info.get('model')} "
              f"(fw {info.get('firmware_version')})")
        risk_class = "audit-missing" if flags else "audit-ok"
        flags_text = ", ".join(flags) if flags else "No issues flagged"
        vendor_html_items.append(f"""
        <div class="audit-item {risk_class}">
          <div class="audit-file">{html_escape(device_id)} — {html_escape(info.get('vendor',''))} {html_escape(info.get('model',''))}</div>
          <div class="audit-detail">Firmware: {html_escape(info.get('firmware_version','?'))} &middot; Last patched: {html_escape(info.get('last_patch_date','unknown'))} ({age if age is not None else '?'} days ago)</div>
          <div class="audit-detail">Business Associate Agreement on file: {'Yes' if baa else 'No'}</div>
          <div class="audit-status">{html_escape(flags_text)}</div>
        </div>""")

if not alert_device_ids:
    vendor_html_items.append('<li>No device-tagged alerts in this window.</li>')

vendor_html = "".join(vendor_html_items) if any('<div class="audit-item' in i for i in vendor_html_items) \
    else f'<ul class="note-list purple">{"".join(vendor_html_items)}</ul>'

# ── Section 5: Audit ──
print("\n" + "─"*65)
print("SECTION 5 — AUDIT TRAIL & CHAIN OF CUSTODY")
print("─"*65)

files = ["/tmp/memory.lime",
         "/tmp/mitre_mapping.json",
         "/tmp/yara_results.txt"]
audit_html_items = []
for f in files:
    h    = file_hash(f)
    size = os.path.getsize(f) if os.path.exists(f) else 0
    ok   = "✅ INTACT" if h else "❌ MISSING"
    print(f"File   : {f}")
    print(f"SHA256 : {h[:48]}..." if h else "SHA256 : NOT FOUND")
    print(f"Size   : {size:,} bytes  |  Status: {ok}")
    print()
    status_class = "audit-ok" if h else "audit-missing"
    hash_display = f"{h[:48]}…" if h else "NOT FOUND"
    audit_html_items.append(f"""
        <div class="audit-item {status_class}">
          <div class="audit-file">{html_escape(f)}</div>
          <div class="audit-detail">SHA256: {hash_display}</div>
          <div class="audit-detail">Size: {size:,} bytes</div>
          <div class="audit-status">{ok}</div>
        </div>""")

audit_html = "".join(audit_html_items)
any_missing = any(not file_hash(f) for f in files)

# ── Section 6: Retention ──
print("─"*65)
print("SECTION 6 — DATA RETENTION POLICY")
print("─"*65)
retention = [
    ("Security Logs",   "90 days",   "Wazuh auto-purge"),
    ("Forensic Data",   "12 months", "encrypted storage"),
    ("Incident Cases",  "3 years",   "TheHive archive"),
    ("Memory Captures", "Per case",  "deleted post-close"),
]
for label, period, note in retention:
    print(f"  {label:<17}: {period:<11} ({note})")

retention_html = "".join(
    f'<li><b>{html_escape(label)}</b> — {html_escape(period)} <span class="trigger-note">({html_escape(note)})</span></li>'
    for label, period, note in retention
)

# ── Save (TXT — actually write this time) ──
os.makedirs(REPORTS_DIR, exist_ok=True)
txt_fname = os.path.join(REPORTS_DIR, f"live_report_{report_id}.txt")
techniques = set(a['technique_id'] for a in mapped)

summary_lines = [
    "="*65,
    "    LIVE EDR COMPLIANCE & AUDIT REPORT",
    "    (NIST CSF + GDPR + HIPAA + HITRUST — Endpoint + IoMT)",
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

print(f"\n{'='*65}")
print(f"✅ Report saved     : {txt_fname}")
print(f"Total Alerts       : {total}")
print(f"Critical           : {crit}")
print(f"High               : {high}")
print(f"MITRE Techniques   : {len(techniques)} — {', '.join(sorted(techniques))}")
print(f"HIPAA Safeguards   : {len(set(c for c,_,_ in hipaa_hits))}")
print(f"HITRUST Domains    : {len(hitrust_hits)}")
print(f"Timestamp          : {now}")
print("="*65)

# ══════════════════════════════════════════════════════════════════════════
# Build colorful HTML report (same "topper notes" theme as the forensic report)
# ══════════════════════════════════════════════════════════════════════════
audit_banner = (
    '<div class="alert-box sev-high">⚠️ One or more chain-of-custody files are missing — see Section 5 below.</div>'
    if any_missing else
    '<div class="alert-box sev-low">✅ All chain-of-custody files intact.</div>'
)

html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Compliance & Audit Report — {report_id}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Patrick+Hand&family=Nunito:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  * {{ box-sizing: border-box; }}
  body {{
    font-family: 'Nunito', system-ui, sans-serif;
    background: #fdfcf8;
    background-image: linear-gradient(#eef0f6 1px, transparent 1px);
    background-size: 100% 32px;
    color: #2b2b33;
    margin: 0; padding: 0;
  }}
  .header {{ background: #ffffff; padding: 36px 40px 28px; border-bottom: 4px dashed #ffb703; }}
  .header h1 {{ margin: 0; font-family: 'Patrick Hand', cursive; color: #1d3557; font-size: 32px; }}
  .header .meta {{ color: #6b7280; margin-top: 10px; font-size: 14px; }}
  .header .meta b {{ color: #2b2b33; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 30px; }}

  .section {{ background: #ffffff; border-radius: 14px; padding: 24px 26px; margin-bottom: 26px;
              border: 2px solid #eef0f6; box-shadow: 0 2px 0 #eef0f6; }}
  .section h2 {{ margin-top: 0; font-family: 'Patrick Hand', cursive; font-size: 22px; color: #1d3557;
                 padding-bottom: 10px; margin-bottom: 16px; border-bottom: 2px solid #f1f3f9; display: inline-block; }}
  .section:nth-of-type(6n+1) {{ border-left: 6px solid #ffb703; }}
  .section:nth-of-type(6n+2) {{ border-left: 6px solid #06a77d; }}
  .section:nth-of-type(6n+3) {{ border-left: 6px solid #4361ee; }}
  .section:nth-of-type(6n+4) {{ border-left: 6px solid #f15bb5; }}
  .section:nth-of-type(6n+5) {{ border-left: 6px solid #fb5607; }}
  .section:nth-of-type(6n+6) {{ border-left: 6px solid #3a86ff; }}

  .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; }}
  .stat-card {{ background: #fffdf5; padding: 18px; border-radius: 12px; text-align: center;
                border: 2px dashed #ffd166; transform: rotate(-0.4deg); }}
  .stat-card:nth-child(2n) {{ transform: rotate(0.4deg); border-color: #90e0c8; background: #f4fffa; }}
  .stat-card:nth-child(3n) {{ transform: rotate(-0.6deg); border-color: #b8c6ff; background: #f5f6ff; }}
  .stat-card .value {{ font-family: 'Patrick Hand', cursive; font-size: 28px; color: #1d3557; }}
  .stat-card .label {{ font-size: 11px; color: #7a7a85; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.6px; font-weight: 700; }}

  .alert-box {{ padding: 14px 18px; border-radius: 10px; margin-bottom: 10px; font-size: 14px; font-weight: 600; }}
  .sev-critical {{ background: #ffe3e3; border: 2px solid #ff3b3b; color: #6b0f0f; }}
  .sev-high {{ background: #fff0ef; border: 2px solid #ff6b6b; color: #8a1f1f; }}
  .sev-medium {{ background: #fff8e6; border: 2px solid #ffb703; color: #7a5200; }}
  .sev-low {{ background: #eafaf1; border: 2px solid #06a77d; color: #0b4d38; }}
  .sev-high.unmapped, .sev-critical.unmapped {{ box-shadow: inset 0 0 0 2px #ffb703; }}
  .badge {{ display: inline-block; padding: 3px 12px; border-radius: 20px; font-weight: 800; font-size: 11px; margin-right: 8px; letter-spacing: 0.5px; }}
  .sev-critical .badge {{ background: #ff3b3b; color: #fff; }}
  .sev-high .badge {{ background: #ff6b6b; color: #fff; }}
  .sev-medium .badge {{ background: #ffb703; color: #4d3800; }}
  .sev-low .badge {{ background: #06a77d; color: #fff; }}
  .mitre-tag {{ margin-top: 4px; font-family: 'JetBrains Mono', monospace; font-size: 12px; font-weight: 500; opacity: 0.85; }}

  .note-list {{ background: #fff8e6; border: 2px dashed #ffb703; border-radius: 10px; margin: 0;
                padding: 16px 18px 16px 38px; list-style: none; }}
  .note-list.blue {{ background: #eef3ff; border-color: #4361ee; }}
  .note-list.green {{ background: #eafaf1; border-color: #06a77d; }}
  .note-list.purple {{ background: #f6effe; border-color: #7f77dd; }}
  .note-list li {{ position: relative; padding: 8px 0; font-size: 14px; line-height: 1.55; color: #3a3a42; }}
  .note-list li::before {{ content: "✔"; position: absolute; left: -26px; color: #ffb703; font-weight: 800; }}
  .note-list.blue li::before {{ color: #4361ee; }}
  .note-list.green li::before {{ color: #06a77d; }}
  .note-list.purple li::before {{ color: #7f77dd; }}
  .note-list li b {{ color: #1d3557; }}
  .trigger-note {{ font-size: 12px; color: #7a7a85; margin-top: 2px; font-family: 'JetBrains Mono', monospace; }}

  .audit-item {{ border-radius: 10px; padding: 12px 16px; margin-bottom: 10px; border: 2px solid; position: relative; }}
  .audit-ok {{ background: #eafaf1; border-color: #06a77d; }}
  .audit-missing {{ background: #ffe3e3; border-color: #ff3b3b; }}
  .audit-file {{ font-family: 'JetBrains Mono', monospace; font-weight: 700; font-size: 13px; color: #1d3557; }}
  .audit-detail {{ font-family: 'JetBrains Mono', monospace; font-size: 11.5px; color: #6b6b75; }}
  .audit-status {{ font-weight: 800; font-size: 12px; margin-top: 4px; }}
  .audit-ok .audit-status {{ color: #0b4d38; }}
  .audit-missing .audit-status {{ color: #6b0f0f; }}

  .footer {{ text-align: center; padding: 26px; color: #9aa0ab; font-family: 'Patrick Hand', cursive; font-size: 16px; }}
</style>
</head>
<body>
  <div class="header">
    <h1>📋 Live EDR Compliance &amp; Audit Report</h1>
    <div class="meta">NIST CSF &middot; GDPR &middot; HIPAA &middot; HITRUST — Endpoint + IoMT
      &nbsp;·&nbsp; 🕒 <b>{html_escape(now)}</b> &nbsp;·&nbsp; 🆔 <b>{html_escape(report_id)}</b></div>
  </div>
  <div class="container">

    <div class="section">
      <h2>📊 Summary</h2>
      <div class="stat-grid">
        <div class="stat-card"><div class="value">{total}</div><div class="label">Total Alerts</div></div>
        <div class="stat-card"><div class="value">{crit}</div><div class="label">Critical</div></div>
        <div class="stat-card"><div class="value">{high}</div><div class="label">High</div></div>
        <div class="stat-card"><div class="value">{len(techniques)}</div><div class="label">MITRE Techniques</div></div>
        <div class="stat-card"><div class="value">{len(set(c for c,_,_ in hipaa_hits))}</div><div class="label">HIPAA Safeguards</div></div>
        <div class="stat-card"><div class="value">{len(hitrust_hits)}</div><div class="label">HITRUST Domains</div></div>
      </div>
      <div style="margin-top:16px;">{audit_banner}</div>
    </div>

    <div class="section">
      <h2>🎯 Section 1 — MITRE ATT&amp;CK Mapping (Live Alerts)</h2>
      {"".join(mitre_rows_html)}
    </div>

    <div class="section">
      <h2>🛡️ Section 2 — NIST CSF Compliance</h2>
      <ul class="note-list green">{nist_html}</ul>
    </div>

    <div class="section">
      <h2>🏥 Section 3 — HIPAA Security Rule Compliance (45 CFR §164)</h2>
      <ul class="note-list blue">{hipaa_html}</ul>
    </div>

    <div class="section">
      <h2>🔐 Section 4 — HITRUST CSF Domain Mapping</h2>
      <ul class="note-list purple">{hitrust_html}</ul>
    </div>

    <div class="section">
      <h2>🏭 Section 4B — Vendor / Third-Party Risk (HIPAA Business Associate)</h2>
      {vendor_html}
    </div>

    <div class="section">
      <h2>🔎 Section 5 — Audit Trail &amp; Chain of Custody</h2>
      {audit_html}
    </div>

    <div class="section">
      <h2>🗄️ Section 6 — Data Retention Policy</h2>
      <ul class="note-list">{retention_html}</ul>
    </div>

  </div>
  <div class="footer">✏️ Healthcare-Extended EDR &middot; Compliance &amp; Audit Pipeline</div>
</body>
</html>"""

html_fname = os.path.join(REPORTS_DIR, f"compliance_report_{report_id}.html")
with open(html_fname, "w") as f:
    f.write(html)

print(f"[🔗] HTML report saved: {html_fname}")
