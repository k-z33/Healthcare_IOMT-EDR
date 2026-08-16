"""
Shared device-safety utilities for Healthcare IoMT EDR.
Single source of truth for PATIENT_SAFETY_DEVICES and device-type inference,
used by live_edr_iomt.py, auto_contain.py, and thehive_integration_iomt.py.
"""

import re

PATIENT_SAFETY_DEVICES = {"ventilator", "infusion_pump", "patient_monitor"}

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
    if device_type:
        return device_type
    if device_id:
        for pattern, canonical_type in DEVICE_ID_PATTERNS:
            if pattern.search(device_id):
                return canonical_type
    return "unknown"


def is_patient_safety_device(device_type: str) -> bool:
    return device_type in PATIENT_SAFETY_DEVICES
