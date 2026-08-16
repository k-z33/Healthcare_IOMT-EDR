#!/usr/bin/env python3
"""One-shot, safe patch: adds persistent error-logging to the silent
except block in live_edr_iomt.py. Makes a .bak first, verifies the
patched file still compiles before leaving it in place."""
import re, shutil, py_compile, sys

TARGET = "live_edr_iomt.py"
ANCHOR = 'print(f"  [REPORT] Warning: could not generate report'

with open(TARGET) as f:
    lines = f.readlines()

patched = False
out = []
for line in lines:
    out.append(line)
    if ANCHOR in line and not patched:
        indent = line[:len(line) - len(line.lstrip())]
        out.append(f'{indent}try:\n')
        out.append(f'{indent}    with open("logs/edr_events.jsonl", "a") as _ef:\n')
        out.append(f'{indent}        _ef.write(json.dumps({{\n')
        out.append(f'{indent}            "event": "report_generation_failed",\n')
        out.append(f'{indent}            "case_id": case_id,\n')
        out.append(f'{indent}            "error": str(rep_err),\n')
        out.append(f'{indent}            "timestamp": datetime.now(timezone.utc).isoformat()\n')
        out.append(f'{indent}        }}) + "\\n")\n')
        out.append(f'{indent}except Exception:\n')
        out.append(f'{indent}    pass\n')
        patched = True

if not patched:
    print("ANCHOR NOT FOUND — no changes made. File is untouched.")
    sys.exit(1)

shutil.copy(TARGET, TARGET + ".bak")
with open(TARGET, "w") as f:
    f.writelines(out)

try:
    py_compile.compile(TARGET, doraise=True)
    print(f"OK — patched and syntax-valid. Backup saved as {TARGET}.bak")
except py_compile.PyCompileError as e:
    shutil.copy(TARGET + ".bak", TARGET)
    print(f"SYNTAX ERROR after patch — reverted automatically. Details:\n{e}")
    sys.exit(1)
