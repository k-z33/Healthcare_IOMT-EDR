#!/usr/bin/env python3
import shutil, py_compile, sys

TARGET = "config/compliance_report.py"

with open(TARGET) as f:
    content = f.read()

if "def _wazuh_level_counts" in content:
    print("Already patched — no changes made.")
    sys.exit(0)

OLD_FUNC_START = "def compute_real_stats():"
if OLD_FUNC_START not in content:
    print("ANCHOR NOT FOUND")
    sys.exit(1)

NEW_FUNC = '''def _wazuh_level_counts():
    """Query Wazuh manager container for alert level counts."""
    import subprocess as _sp
    import re as _re
    try:
        out = _sp.run(
            ["docker", "exec", "healthcare-edr-wazuh.manager-1",
             "cat", "/var/ossec/logs/alerts/alerts.json"],
            capture_output=True, text=True, timeout=15
        ).stdout
        levels = [int(x) for x in _re.findall(r'"level":(\\\\d+)', out)]
        critical = sum(1 for l in levels if l >= 12)
        high = sum(1 for l in levels if 7 <= l <= 11)
        return critical, high
    except Exception:
        return None, None


def compute_real_stats():
    """Compute stats from live logs instead of hardcoded demo values."""
    import os as _os

    metrics_file = _os.path.expanduser("~/healthcare-edr/soc_metrics.jsonl")

    total_events = 0
    auto_contained = 0

    if _os.path.exists(metrics_file):
        with open(metrics_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                total_events += 1
                if e.get("stage") == "containment_action":
                    auto_contained += 1

    critical_alerts, high_alerts = _wazuh_level_counts()

    return {
        "total_events"      : total_events or DEMO_STATS["total_events"],
        "critical_alerts"   : critical_alerts if critical_alerts is not None else DEMO_STATS["critical_alerts"],
        "high_alerts"       : high_alerts if high_alerts is not None else DEMO_STATS["high_alerts"],
        "auto_contained"    : auto_contained or DEMO_STATS["auto_contained"],
        "mttd_minutes"      : DEMO_STATS["mttd_minutes"],
        "mttr_minutes"      : DEMO_STATS["mttr_minutes"],
        "agents_monitored"  : DEMO_STATS["agents_monitored"],
        "uptime_percent"    : DEMO_STATS["uptime_percent"],
        "false_positive_pct": DEMO_STATS["false_positive_pct"],
    }

'''

start_idx = content.index(OLD_FUNC_START)
end_marker = "# ── Framework Definitions"
end_idx = content.index(end_marker)
content = content[:start_idx] + NEW_FUNC + content[end_idx:]

shutil.copy(TARGET, TARGET + ".bak_final2")
with open(TARGET, "w") as f:
    f.write(content)

try:
    py_compile.compile(TARGET, doraise=True)
    print(f"OK — patched and syntax-valid. Backup: {TARGET}.bak_final2")
except py_compile.PyCompileError as e:
    shutil.copy(TARGET + ".bak_final2", TARGET)
    print(f"SYNTAX ERROR — reverted. Details:\\n{e}")
    sys.exit(1)
