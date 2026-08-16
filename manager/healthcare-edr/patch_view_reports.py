#!/usr/bin/env python3
"""
patch_view_reports.py

Adds a working --latest N flag to view_all_reports.py by wrapping the
existing print_section() function — does not touch any of the rest of
the file (including any Location/Forensics fields already added), so
nothing else can break. Makes a .bak first and verifies the patched
file still compiles before leaving it in place.
"""
import shutil, py_compile, sys

TARGET = "view_all_reports.py"
ANCHOR = "def main():"

PATCH = '''import argparse as _argparse
_arg_parser = _argparse.ArgumentParser()
_arg_parser.add_argument("--latest", type=int, default=None,
                          help="Show only latest N reports per category")
_ARGS, _ = _arg_parser.parse_known_args()

_original_print_section = print_section
def print_section(title, reports, max_show=None):
    if _ARGS.latest:
        max_show = _ARGS.latest
    return _original_print_section(title, reports, max_show)

'''

with open(TARGET) as f:
    content = f.read()

if ANCHOR not in content:
    print("ANCHOR NOT FOUND — no changes made. File is untouched.")
    sys.exit(1)

if "_arg_parser" in content:
    print("Already patched — no changes made.")
    sys.exit(0)

patched_content = content.replace(ANCHOR, PATCH + ANCHOR, 1)

shutil.copy(TARGET, TARGET + ".bak")
with open(TARGET, "w") as f:
    f.write(patched_content)

try:
    py_compile.compile(TARGET, doraise=True)
    print(f"OK — patched and syntax-valid. Backup saved as {TARGET}.bak")
    print("Try: python3 view_all_reports.py --latest 3")
except py_compile.PyCompileError as e:
    shutil.copy(TARGET + ".bak", TARGET)
    print(f"SYNTAX ERROR after patch — reverted automatically. Details:\\n{e}")
    sys.exit(1)
