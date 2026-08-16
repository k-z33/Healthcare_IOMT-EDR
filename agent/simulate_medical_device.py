"""
simulate_medical_device.py  (Endpoint machine — AWS)

Simulates network/protocol events for medical/IoMT devices, covering
all 20 detection scenarios in iomt_custom_rules.xml. Five device
categories are modeled, each with its own normal baseline.

Usage examples:
    python3 simulate_medical_device.py --device dental-xray-01 --mode normal --count 5
    python3 simulate_medical_device.py --device infusion-pump-03 --mode firmware_attempt
    python3 simulate_medical_device.py --device ventilator-02 --mode brute_force
    python3 simulate_medical_device.py --list-modes

Writes JSON log lines to /var/log/iomt/medical_device.log.
"""

import argparse
import json
import os
import random
import time
from datetime import datetime, timezone

LOG_PATH = "/var/log/iomt/medical_device.log"

DEVICE_PROFILES = {
    "dental-xray-01": {
        "type": "imaging",
        "normal_ip": "10.0.0.5",
        "normal_port": 104,
        "byte_range": (47000, 53000),
        "normal_hours": [9, 10, 14, 15],
    },
    "infusion-pump-03": {
        "type": "infusion_pump",
        "normal_ip": "10.0.0.12",
        "normal_port": 2575,
        "byte_range": (500, 1500),
        "normal_hours": list(range(0, 24)),
    },
    "patient-monitor-07": {
        "type": "patient_monitor",
        "normal_ip": "10.0.0.20",
        "normal_port": 2575,
        "byte_range": (2000, 4000),
        "normal_hours": list(range(0, 24)),
    },
    "ventilator-02": {
        "type": "ventilator",
        "normal_ip": "10.0.0.25",
        "normal_port": 2575,
        "byte_range": (1000, 2500),
        "normal_hours": list(range(0, 24)),
    },
    "pharmacy-cabinet-01": {
        "type": "pharmacy_dispensing",
        "normal_ip": "10.0.0.40",
        "normal_port": 8443,
        "byte_range": (3000, 8000),
        "normal_hours": list(range(7, 19)),
    },
}

# Maps each mode to (rule(s) it should trigger, and how to build the event)
MODES = [
    "normal",             # baseline, no rule triggered
    "unknown_ip",         # rule 100201
    "unknown_port",       # rule 100202
    "volume_spike",       # rule 100203
    "odd_hour",           # rule 100204
    "flooding",           # rule 100205 (fires --count rapid events automatically)
    "firmware_attempt",   # rule 100206
    "legacy_protocol",    # rule 100207
    "default_credential", # rule 100208
    "auth_failed",        # rule 100209 (fires --count rapid events automatically)
    "mac_ip_mismatch",    # rule 100210
    "replay_suspected",   # rule 100211
    "unencrypted_phi",    # rule 100212
    "time_sync_anomaly",  # rule 100213
    "cross_segment",      # rule 100214
    "dicom_exfiltration", # rule 100221
    "hl7_tampering",      # rule 100222
    "device_reboot",      # rule 100223
    "config_change",      # rule 100224
    "network_scan",       # rule 100225
]


def base_fields(device_id: str) -> dict:
    profile = DEVICE_PROFILES[device_id]
    return {
        "device_id": device_id,
        "device_type": profile["type"],
        "dest_ip": profile["normal_ip"],
        "dest_port": profile["normal_port"],
        "bytes_sent": random.randint(*profile["byte_range"]),
        "hour_of_day": random.choice(profile["normal_hours"]),
        "event": "connection",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def build_event(device_id: str, mode: str) -> dict:
    profile = DEVICE_PROFILES[device_id]
    event = base_fields(device_id)

    if mode == "normal":
        pass

    elif mode == "unknown_ip":
        event["dest_ip"] = "203.0.113.44"

    elif mode == "unknown_port":
        event["dest_port"] = 445

    elif mode == "volume_spike":
        event["bytes_sent"] = profile["byte_range"][1] * 20

    elif mode == "odd_hour":
        event["hour_of_day"] = 3

    elif mode == "flooding":
        pass  # rapid repeated calls handled by --count/--interval in main loop

    elif mode == "firmware_attempt":
        event["event"] = "firmware_update_request"
        event["dest_ip"] = "198.51.100.9"
        event["bytes_sent"] = 500000

    elif mode == "legacy_protocol":
        event["event"] = "legacy_protocol_used"
        event["protocol"] = random.choice(["telnet", "ftp", "http"])

    elif mode == "default_credential":
        event["event"] = "default_credential_login"
        event["username_used"] = "admin"

    elif mode == "auth_failed":
        event["event"] = "auth_failed"
        event["username_used"] = "admin"

    elif mode == "mac_ip_mismatch":
        event["event"] = "mac_ip_mismatch"
        event["expected_mac"] = "AA:BB:CC:00:11:22"
        event["observed_mac"] = "DE:AD:BE:EF:00:99"

    elif mode == "replay_suspected":
        event["event"] = "replay_suspected"
        event["duplicate_sequence_id"] = 10245

    elif mode == "unencrypted_phi":
        event["event"] = "unencrypted_phi_transmission"
        event["protocol"] = random.choice(["dicom", "hl7"])
        event["encrypted"] = False

    elif mode == "time_sync_anomaly":
        event["event"] = "time_sync_anomaly"
        event["clock_drift_seconds"] = random.randint(500, 5000)

    elif mode == "cross_segment":
        event["event"] = "cross_segment_access"
        event["source_segment"] = "clinical_vlan"
        event["target_segment"] = "billing_vlan"

    elif mode == "dicom_exfiltration":
        event["event"] = "dicom_exfiltration"
        event["dest_ip"] = "203.0.113.77"
        event["images_transferred"] = random.randint(50, 500)

    elif mode == "hl7_tampering":
        event["event"] = "hl7_tampering"
        event["segment_modified"] = random.choice(["PID", "OBX", "ORC"])

    elif mode == "device_reboot":
        event["event"] = "device_reboot"
        event["authorized"] = False

    elif mode == "config_change":
        event["event"] = "config_change"
        event["authorized"] = False
        event["changed_setting"] = random.choice(
            ["dosage_limit", "alarm_threshold", "network_config", "firmware_channel"]
        )

    elif mode == "network_scan":
        event["event"] = "network_scan_detected"
        event["ports_scanned"] = random.randint(20, 200)

    else:
        raise ValueError(f"Unknown mode: {mode}")

    return event


def write_log(entry: dict):
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print("Logged:", entry)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--device", choices=list(DEVICE_PROFILES.keys()), default="dental-xray-01")
    parser.add_argument("--mode", choices=MODES, default="normal")
    parser.add_argument("--count", type=int, default=5)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--list-modes", action="store_true")
    args = parser.parse_args()

    if args.list_modes:
        print("Available modes (map to iomt_custom_rules.xml rule IDs):")
        print("  normal              -> no alert (baseline)")
        print("  unknown_ip          -> rule 100201")
        print("  unknown_port        -> rule 100202")
        print("  volume_spike        -> rule 100203")
        print("  odd_hour            -> rule 100204")
        print("  flooding            -> rule 100205 (use high --count, low --interval)")
        print("  firmware_attempt    -> rule 100206")
        print("  legacy_protocol     -> rule 100207")
        print("  default_credential  -> rule 100208")
        print("  auth_failed         -> rule 100209 (use --count 6+ within 60s)")
        print("  mac_ip_mismatch     -> rule 100210")
        print("  replay_suspected    -> rule 100211")
        print("  unencrypted_phi     -> rule 100212")
        print("  time_sync_anomaly   -> rule 100213")
        print("  cross_segment       -> rule 100214")
        print("  dicom_exfiltration  -> rule 100221")
        print("  hl7_tampering       -> rule 100222")
        print("  device_reboot       -> rule 100223")
        print("  config_change       -> rule 100224")
        print("  network_scan        -> rule 100225")
        print("  (device-type rules 100215-100219 fire automatically based on --device)")
        print("  (correlation rule 100220 fires if 2+ anomaly types hit the same device within 30s)")
        raise SystemExit(0)

    for i in range(args.count):
        entry = build_event(args.device, args.mode)
        write_log(entry)
        if i < args.count - 1:
            time.sleep(args.interval)
