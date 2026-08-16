"""
network_security_extensions.py  (Manager machine — AWS)

Extends iomt_guard_ml.py with eight additional network-security detection
concepts, built as small, focused classes that plug into the existing
HybridGuard pipeline. Each concept is explained in its class docstring.

    1. ARPMonitor              -> ARP spoofing / MITM detection
    2. PortScanDetector         -> formalized port-scan counting logic
    3. DeviceRegistry           -> rogue/unauthorized new device detection
    4. ZoneValidator            -> network segmentation (VLAN) validation
    5. TLSValidator             -> certificate / encryption validation
    6. day_of_week feature       -> added to ML feature engineering
    7. RogueDHCPDetector        -> rogue DHCP server detection
    8. FirewallViolationLogger  -> firewall/ACL violation logging

These are intentionally lightweight, rule-based, and dependency-free
(no new libraries) so they integrate directly with the existing
JSON-log-line pattern used by simulate_medical_device.py.
"""

import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone


# =====================================================================
# 1. ARP Spoofing / MITM Detection
# =====================================================================
class ARPMonitor:
    """
    Concept: every device's IP should always map to the same MAC address.
    If a MAC address suddenly changes for a known IP (or two IPs claim
    the same MAC), that's a classic sign of ARP spoofing / a
    man-in-the-middle attack.
    """

    def __init__(self):
        self.known_ip_to_mac = {}  # e.g. {"10.0.0.5": "AA:BB:CC:00:11:22"}

    def register_baseline(self, ip: str, mac: str):
        self.known_ip_to_mac[ip] = mac

    def check(self, ip: str, observed_mac: str):
        expected = self.known_ip_to_mac.get(ip)
        if expected is None:
            return None  # unknown IP, not this check's job (handled elsewhere)
        if observed_mac != expected:
            return {
                "event": "arp_spoofing_suspected",
                "ip": ip,
                "expected_mac": expected,
                "observed_mac": observed_mac,
            }
        return None


# =====================================================================
# 2. Port Scan Detection (formalized counting logic)
# =====================================================================
class PortScanDetector:
    """
    Concept: a port scan is "one source IP touching many distinct ports
    on a target within a short window." A single unexpected port
    (handled by rule 100202) is not a scan; a burst across many ports
    IS a scan. We track a rolling window of (timestamp, port) per
    source IP.
    """

    def __init__(self, distinct_port_threshold: int = 10, window_seconds: int = 30):
        self.threshold = distinct_port_threshold
        self.window_seconds = window_seconds
        self.history = defaultdict(deque)  # source_ip -> deque[(timestamp, port)]

    def record_and_check(self, source_ip: str, port: int, timestamp: datetime):
        dq = self.history[source_ip]
        dq.append((timestamp, port))

        # drop entries outside the window
        cutoff = timestamp.timestamp() - self.window_seconds
        while dq and dq[0][0].timestamp() < cutoff:
            dq.popleft()

        distinct_ports = {p for _, p in dq}
        if len(distinct_ports) >= self.threshold:
            return {
                "event": "port_scan_detected",
                "source_ip": source_ip,
                "distinct_ports_touched": len(distinct_ports),
                "window_seconds": self.window_seconds,
            }
        return None


# =====================================================================
# 3. Rogue / Unauthorized Device Detection
# =====================================================================
class DeviceRegistry:
    """
    Concept: every legitimate medical device should be pre-registered
    (asset inventory). If traffic arrives from a device_id that was
    never registered, it's either a misconfigured new device or a
    rogue/unauthorized one -- either way it needs review before being
    trusted.
    """

    def __init__(self, known_devices: set = None):
        self.known_devices = known_devices or set()

    def register(self, device_id: str):
        self.known_devices.add(device_id)

    def check(self, device_id: str):
        if device_id not in self.known_devices:
            return {
                "event": "rogue_device_detected",
                "device_id": device_id,
            }
        return None


# =====================================================================
# 4. Network Segmentation (VLAN/Zone) Validation
# =====================================================================
class ZoneValidator:
    """
    Concept: each device type should only ever be allowed to reach
    specific network zones. A dental X-ray machine reaching the
    billing/admin zone is a segmentation violation, regardless of
    whether the IP itself looks "known."
    """

    ALLOWED_ZONES = {
        "imaging": {"clinical_vlan", "imaging_vlan"},
        "infusion_pump": {"clinical_vlan"},
        "patient_monitor": {"clinical_vlan"},
        "ventilator": {"clinical_vlan"},
        "pharmacy_dispensing": {"clinical_vlan", "pharmacy_vlan"},
    }

    def check(self, device_type: str, target_zone: str):
        allowed = self.ALLOWED_ZONES.get(device_type, set())
        if target_zone not in allowed:
            return {
                "event": "zone_violation",
                "device_type": device_type,
                "target_zone": target_zone,
                "allowed_zones": list(allowed),
            }
        return None


# =====================================================================
# 5. TLS / Certificate Validation
# =====================================================================
class TLSValidator:
    """
    Concept: any medical device transmitting PHI-carrying protocols
    should use a valid, non-expired, non-self-signed certificate.
    This check flags the three most common real-world failures.
    """

    def check(self, encrypted: bool, cert_valid: bool = True, cert_expired: bool = False,
               self_signed: bool = False):
        issues = []
        if not encrypted:
            issues.append("unencrypted_channel")
        if not cert_valid:
            issues.append("invalid_certificate")
        if cert_expired:
            issues.append("expired_certificate")
        if self_signed:
            issues.append("self_signed_certificate")

        if issues:
            return {"event": "tls_validation_failed", "issues": issues}
        return None


# =====================================================================
# 6. day_of_week feature for ML (extends iomt_guard_ml.py's feature vector)
# =====================================================================
def event_to_features_extended(event: dict) -> list:
    """
    Drop-in replacement for iomt_guard_ml.py's event_to_features().
    Adds day_of_week (0=Monday .. 6=Sunday) so the Isolation Forest
    model can learn weekday-vs-weekend traffic pattern differences,
    not just hour-of-day.
    """
    ts = event.get("timestamp")
    if ts:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        day_of_week = dt.weekday()
    else:
        day_of_week = 0
    return [event.get("bytes_sent", 0), event.get("dest_port", 0),
            event.get("hour_of_day", 0), day_of_week]


# =====================================================================
# 7. Rogue DHCP Server Detection
# =====================================================================
class RogueDHCPDetector:
    """
    Concept: only one (or a known set of) DHCP server(s) should be
    handing out IP addresses on the clinical network. If a device
    reports receiving a DHCP offer from an unrecognized server IP,
    that's a strong sign of a rogue DHCP server (used for MITM/DNS
    hijacking attacks).
    """

    def __init__(self, authorized_dhcp_servers: set):
        self.authorized_servers = authorized_dhcp_servers

    def check(self, dhcp_server_ip: str):
        if dhcp_server_ip not in self.authorized_servers:
            return {
                "event": "rogue_dhcp_detected",
                "dhcp_server_ip": dhcp_server_ip,
            }
        return None


# =====================================================================
# 8. Firewall / ACL Violation Logging
# =====================================================================
class FirewallViolationLogger:
    """
    Concept: even if a connection gets blocked by the firewall (so no
    harm done), the *attempt itself* is valuable security telemetry.
    Repeated blocked attempts from the same device often precede a
    successful compromise attempt elsewhere.
    """

    def __init__(self):
        self.violations = []

    def log(self, device_id: str, attempted_dest: str, attempted_port: int, action: str = "blocked"):
        entry = {
            "event": "firewall_violation",
            "device_id": device_id,
            "attempted_dest": attempted_dest,
            "attempted_port": attempted_port,
            "action": action,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.violations.append(entry)
        return entry


# =====================================================================
# DEMO — exercise all eight concepts with simple, readable examples
# =====================================================================
if __name__ == "__main__":
    print("=== 1. ARP Monitor ===")
    arp = ARPMonitor()
    arp.register_baseline("10.0.0.5", "AA:BB:CC:00:11:22")
    result = arp.check("10.0.0.5", "DE:AD:BE:EF:00:99")
    print(result)

    print("\n=== 2. Port Scan Detector ===")
    scanner = PortScanDetector(distinct_port_threshold=5, window_seconds=30)
    now = datetime.now(timezone.utc)
    for port in [22, 80, 443, 8080, 3389, 5900]:
        result = scanner.record_and_check("10.0.0.99", port, now)
    print(result)

    print("\n=== 3. Device Registry (rogue device) ===")
    registry = DeviceRegistry(known_devices={"dental-xray-01", "infusion-pump-03"})
    print(registry.check("unknown-device-99"))
    print(registry.check("dental-xray-01"))

    print("\n=== 4. Zone Validator ===")
    zones = ZoneValidator()
    print(zones.check("infusion_pump", "billing_vlan"))
    print(zones.check("infusion_pump", "clinical_vlan"))

    print("\n=== 5. TLS Validator ===")
    tls = TLSValidator()
    print(tls.check(encrypted=False))
    print(tls.check(encrypted=True, cert_expired=True))
    print(tls.check(encrypted=True))

    print("\n=== 6. day_of_week feature ===")
    sample_event = {"bytes_sent": 50000, "dest_port": 104, "hour_of_day": 9,
                     "timestamp": "2026-08-03T09:00:00+00:00"}
    print(event_to_features_extended(sample_event))

    print("\n=== 7. Rogue DHCP Detector ===")
    dhcp = RogueDHCPDetector(authorized_dhcp_servers={"10.0.0.1"})
    print(dhcp.check("10.0.0.250"))
    print(dhcp.check("10.0.0.1"))

    print("\n=== 8. Firewall Violation Logger ===")
    fw = FirewallViolationLogger()
    print(fw.log("infusion-pump-03", "203.0.113.44", 445))
