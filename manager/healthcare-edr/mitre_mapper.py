import subprocess
import json
from datetime import datetime

CONTAINER = "healthcare-edr-wazuh.manager-1"   # AWS setup — badlo agar Mac single-node pe chalana ho

MITRE_MAP = {
    # ── Original endpoint (Windows/Linux LoTL) techniques ─────────────────
    "ransomware":     ("T1486", "Impact",              "Data Encrypted for Impact"),
    "powershell":      ("T1059", "Execution",            "Command and Scripting Interpreter"),
    "wmi":             ("T1047", "Execution",            "WMI Execution"),
    "encoded":         ("T1027", "Defense Evasion",      "Obfuscated Files"),
    "injection":       ("T1055", "Defense Evasion",      "Process Injection"),
    "scheduled":       ("T1053", "Persistence",          "Scheduled Task"),
    "download":        ("T1105", "Command and Control",  "Ingress Tool Transfer"),
    "user creation":   ("T1136", "Persistence",          "Create Account"),
    "deletion":        ("T1485", "Impact",               "Data Destruction"),
    "integrity":       ("T1565", "Impact",               "Data Manipulation"),
    "login":           ("T1078", "Defense Evasion",      "Valid Accounts"),
    "office":          ("T1566", "Initial Access",       "Phishing"),
    "shell":           ("T1059", "Execution",            "Command Shell"),
    "script":          ("T1059", "Execution",            "Scripting"),
    "group":           ("T1069", "Discovery",            "Permission Groups Discovery"),

    # ── IoMT / Medical Device techniques (healthcare-extended layer) ──────
    "unknown destination ip":  ("T1071",   "Command and Control", "Application Layer Protocol"),
    "unexpected port":         ("T1571",   "Command and Control", "Non-Standard Port"),
    "data volume spike":       ("T1030",   "Exfiltration",        "Data Transfer Size Limits"),
    "off-hour":                ("T1078",   "Defense Evasion",     "Valid Accounts (Anomalous Timing)"),
    "flooding":                ("T1499",   "Impact",              "Endpoint Denial of Service"),
    "firmware":                ("T1542",   "Persistence",         "Pre-OS Boot / Firmware Tampering"),
    "legacy protocol":         ("T1040",   "Discovery",           "Network Sniffing (Plaintext Protocol)"),
    "default credential":      ("T1078.001","Defense Evasion",    "Default Accounts"),
    "failed authentication":   ("T1110",   "Credential Access",   "Brute Force"),
    "brute force":             ("T1110",   "Credential Access",   "Brute Force"),
    "impersonation":           ("T1557",   "Collection",          "Adversary-in-the-Middle (MAC/IP Spoofing)"),
    "replay":                  ("T1550",   "Defense Evasion",     "Use Alternate Authentication Material"),
    "unencrypted phi":         ("T1020",   "Exfiltration",        "Automated Exfiltration (Unencrypted PHI)"),
    "time sync":               ("T1070.006","Defense Evasion",   "Timestomp"),
    "cross-segment":           ("T1210",   "Lateral Movement",    "Exploitation of Remote Services"),
    "infusion pump":           ("T0836",   "Impact (ICS/Medical)","Modify Parameter — Patient Dosing Risk"),
    "ventilator":              ("T0836",   "Impact (ICS/Medical)","Modify Parameter — Life-Support Risk"),
    "patient monitor":         ("T0836",   "Impact (ICS/Medical)","Modify Parameter — Vitals Integrity"),
    "dicom":                   ("T1537",   "Exfiltration",        "Transfer Data to Cloud Account (DICOM/Image Exfil)"),
    "diversion":                ("T1078",  "Initial Access",      "Valid Accounts — Pharmacy Insider Threat"),
    "hl7":                     ("T1565",   "Impact",              "Data Manipulation — HL7 Message Tampering"),
    "reboot":                  ("T1529",   "Impact",              "System Shutdown/Reboot"),
    "config change":           ("T1562",   "Defense Evasion",     "Impair Defenses — Unauthorized Config Change"),
    "network scan":            ("T1046",   "Discovery",           "Network Service Discovery"),
    "rogue device":            ("T1200",   "Initial Access",      "Hardware Additions — Unregistered Device"),
    "rogue dhcp":              ("T1557",   "Collection",          "Adversary-in-the-Middle — Rogue DHCP"),
    "zone violation":           ("T1210",  "Lateral Movement",    "Network Segmentation Violation"),
    "tls validation":           ("T1040",  "Credential Access",   "Transmission Security — Encryption Failure"),
    "port scan":                ("T1046",  "Discovery",           "Port Scan"),
    "multiple anomaly":         ("T0836",  "Impact (ICS/Medical)","Correlated Multi-Indicator Device Compromise"),
}


MITRE_MAP.update({
    "connection event logged":   ("T1071",    "Command and Control",  "Application Layer Protocol (Device Communication Log)"),
    "outside normal operating":  ("T1078",    "Defense Evasion",      "Valid Accounts (Anomalous Timing)"),
    "default or weak credential":("T1078.001","Defense Evasion",      "Default Accounts"),
    "authentication failed":     ("T1110",    "Credential Access",    "Brute Force"),
    "without encryption":        ("T1020",    "Exfiltration",         "Automated Exfiltration (Unencrypted PHI)"),
    "time-sync":                 ("T1070.006","Defense Evasion",      "Timestomp"),
    "network segment":           ("T1210",    "Lateral Movement",     "Exploitation of Remote Services"),
    "configuration change":      ("T1562",    "Defense Evasion",      "Impair Defenses — Unauthorized Config Change"),
    "reconnaissance":            ("T1046",    "Discovery",            "Network Service Discovery"),
    "arp spoofing":              ("T1557",    "Collection",           "Adversary-in-the-Middle (ARP Spoofing)"),
    "mitm":                      ("T1557",    "Collection",           "Adversary-in-the-Middle"),
    "segmentation violation":    ("T1210",    "Lateral Movement",     "Network Segmentation Violation"),
    "certificate validation":    ("T1040",    "Credential Access",    "Transmission Security — Encryption Failure"),
    "firewall":                  ("T1046",    "Discovery",            "Network Service Discovery (Firewall Probing)"),
})


def map_mitre(description):
    d = description.lower()
    for keyword, (tid, tactic, tech) in MITRE_MAP.items():
        if keyword in d:
            return tid, tactic, tech
    return "T0000", "Unknown", "Unclassified"


def get_alerts_from_docker(limit=50):
    """live_edr.py jaise Docker se seedha padho"""
    try:
        cmd = [
            "docker", "exec", CONTAINER,
            "tail", f"-{limit*3}",
            "/var/ossec/logs/alerts/alerts.json"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        alerts = []
        for line in result.stdout.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            try:
                a = json.loads(line)
                alerts.append(a)
            except:
                continue
        return alerts[-limit:] if len(alerts) > limit else alerts
    except Exception as e:
        print(f"Docker error: {e}")
        return []


# ── Main (sirf tab chalta hai jab yeh file directly run ho, import hone pe nahi) ──
if __name__ == "__main__":
    print("\n" + "="*60)
    print("     LIVE MITRE ATT&CK MAPPING REPORT (Endpoint + IoMT)")
    print("="*60)
    print(f"Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Source   : Docker → {CONTAINER}")
    print("="*60)

    alerts = get_alerts_from_docker(limit=50)
    print(f"✅ Docker se {len(alerts)} live alerts mile\n")

    mapped = []
    seen   = set()
    for a in alerts:
        desc     = a.get('rule', {}).get('description', 'unknown')
        level    = int(a.get('rule', {}).get('level', 0))
        agent    = a.get('agent', {}).get('name', 'unknown')
        ts       = a.get('timestamp', '')[:19]
        rule_id  = a.get('rule', {}).get('id', '')
        device_id = a.get('data', {}).get('device_id', '')

        sev = "CRITICAL" if level >= 15 else \
              "HIGH"     if level >= 12 else \
              "MEDIUM"   if level >= 7  else "LOW"

        tid, tactic, tech = map_mitre(desc)

        # skip duplicates
        key = f"{rule_id}_{desc}"
        if key in seen:
            continue
        seen.add(key)

        entry = {
            "timestamp":   ts,
            "agent":       agent,
            "device_id":   device_id or None,
            "description": desc,
            "rule_id":     rule_id,
            "level":       level,
            "severity":    sev,
            "mitre_id":    tid,
            "tactic":      tactic,
            "technique":   tech,
        }
        mapped.append(entry)

        device_tag = f" | Device: {device_id}" if device_id else ""
        print(f"[{sev}] {desc[:52]}")
        print(f"  Agent: {agent}{device_tag} | Level: {level} | {tid} — {tactic}")
        print()

    # Save
    with open("/tmp/mitre_mapping.json", "w") as f:
        json.dump(mapped, f, indent=2)

    techniques = set(a['mitre_id'] for a in mapped)
    print("="*60)
    print(f"✅ {len(mapped)} unique alerts mapped")
    print(f"✅ MITRE Techniques: {len(techniques)} — {', '.join(sorted(techniques))}")
    print(f"✅ Saved: /tmp/mitre_mapping.json")
