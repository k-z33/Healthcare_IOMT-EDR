"""
Shared device-safety utilities for Healthcare IoMT EDR.
Single source of truth for PATIENT_SAFETY_DEVICES and device-type inference,
used by live_edr_iomt.py, auto_contain.py, and thehive_integration_iomt.py.
"""

import re

# Devices where blind network isolation is itself a patient-safety risk —
# these must NEVER be auto-isolated, only escalated.
PATIENT_SAFETY_DEVICES = {"ventilator", "infusion_pump", "patient_monitor"}

# Ordered list of (regex pattern, canonical device_type).
# Matched against device_id when device_type is missing/empty.
# Order matters: more specific patterns first.
DEVICE_ID_PATTERNS = [
    (re.compile(r"ventilator", re.IGNORECASE), "ventilator"),
    (re.compile(r"infusion[-_]?pump", re.IGNORECASE), "infusion_pump"),
    (re.compile(r"patient[-_]?monitor", re.IGNORECASE), "patient_monitor"),
    (re.compile(r"dental[-_]?x[-_]?ray", re.IGNORECASE), "imaging"),
    (re.compile(r"x[-_]?ray|mri|ct[-_]?scan|ultrasound", re.IGNORECASE), "imaging"),
    (re.compile(r"ecg|ekg", re.IGNORECASE), "ecg"),
    (re.compile(r"pump", re.IGNORECASE), "infusion_pump"),
    (re.compile(r"monitor", re.IGNORECASE), "patient_monitor"),
]


def infer_device_type(device_id: str = "", device_type: str = "") -> str:
    """
    Return a safe, non-empty device_type.
    If device_type is already provided, trust it.
    Otherwise, infer from device_id naming pattern.
    Falls back to 'unknown' only if no pattern matches — never silently
    treats an unrecognized device as a plain endpoint.
    """
    if device_type:
        return device_type

    if device_id:
        for pattern, canonical_type in DEVICE_ID_PATTERNS:
            if pattern.search(device_id):
                return canonical_type

    return "unknown"


def is_patient_safety_device(device_type: str) -> bool:
    return device_type in PATIENT_SAFETY_DEVICES
