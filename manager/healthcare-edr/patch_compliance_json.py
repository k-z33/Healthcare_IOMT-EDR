#!/usr/bin/env python3
"""
patch_compliance_json.py

Fixes view_all_reports.py so the Compliance section also picks up
the JSON reports from ~/edr-compliance-reports (NIST/PCI-DSS/ISO27001),
not just the *.html files in compliance_reports/. Only adds to the
existing comp_reports list — nothing else in the file is touched.
Makes a .bak first and verifies the patched file still compiles
before leaving it in place.
"""
import shutil, py_compile, sys

TARGET = "view_all_reports.py"
ANCHOR = '    print_section("📜 Compliance Reports (NIST/HIPAA/HITRUST)", comp_reports, max_show=5)'

PATCH_BEFORE = '''    comp_reports_json = list_reports_in_dir(
        "~/edr-compliance-reports",
        "*.json",
        "Compliance Report (NIST/PCI-DSS/ISO27001 JSON)"
    )
    comp_reports = comp_reports + comp_reports_json
    comp_reports.sort(key=lambda x: x["time"], reverse=True)
'''

with open(TARGET) as f:
    content = f.read()

if ANCHOR not in content:
    print("ANCHOR NOT FOUND — no changes made. File is untouched.")
    sys.exit(1)

if "comp_reports_json" in content:
    print("Already patched — no changes made.")
    sys.exit(0)

patched_content = content.replace(ANCHOR, PATCH_BEFORE + ANCHOR, 1)

shutil.copy(TARGET, TARGET + ".bak2_json_fix")
with open(TARGET, "w") as f:
    f.write(patched_content)

try:
    py_compile.compile(TARGET, doraise=True)
    print(f"OK — patched and syntax-valid. Backup saved as {TARGET}.bak2_json_fix")
    print("Try: python3 view_all_reports.py --latest 5")
except py_compile.PyCompileError as e:
    shutil.copy(TARGET + ".bak2_json_fix", TARGET)
    print(f"SYNTAX ERROR after patch — reverted automatically. Details:\\n{e}")
    sys.exit(1)
