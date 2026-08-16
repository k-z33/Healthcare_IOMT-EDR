#!/usr/bin/env python3
"""
patch_use_real_stats.py
Replaces the 3 remaining DEMO_STATS usages (lines ~218, 237, 272)
with a single computed `stats = compute_real_stats()` call, so the
report actually reflects live soc_metrics.jsonl data.
"""
import shutil, py_compile, sys

TARGET = "config/compliance_report.py"

with open(TARGET) as f:
    content = f.read()

if "stats = compute_real_stats()" in content:
    print("Already patched — no changes made.")
    sys.exit(0)

replacements = [
    ("controls  = get_controls(framework, DEMO_STATS)",
     "stats = compute_real_stats()\n    controls  = get_controls(framework, stats)"),
    ('"statistics"      : DEMO_STATS,',
     '"statistics"      : stats,'),
    ("for k, v in DEMO_STATS.items():",
     "for k, v in stats.items():"),
]

changed = 0
for old, new in replacements:
    if old in content:
        content = content.replace(old, new, 1)
        changed += 1

if changed != 3:
    print(f"WARNING — only {changed}/3 replacements matched. No changes written. Check manually.")
    sys.exit(1)

shutil.copy(TARGET, TARGET + ".bak_use_real")
with open(TARGET, "w") as f:
    f.write(content)

try:
    py_compile.compile(TARGET, doraise=True)
    print(f"OK — patched and syntax-valid. Backup: {TARGET}.bak_use_real")
except py_compile.PyCompileError as e:
    shutil.copy(TARGET + ".bak_use_real", TARGET)
    print(f"SYNTAX ERROR — reverted. Details:\\n{e}")
    sys.exit(1)
