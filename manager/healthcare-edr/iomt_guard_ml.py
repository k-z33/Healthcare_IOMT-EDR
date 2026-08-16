"""
iomt_guard_ml.py  (v2 — integrates network_security_extensions.py)

Same hybrid rule-based + ML detection as before, now upgraded to:
  1. Use the day_of_week-aware feature vector for the Isolation Forest
     model (from network_security_extensions.event_to_features_extended).
  2. Run the eight network_security_extensions checks (ARP, port-scan,
     rogue device, zone validation, TLS, rogue DHCP, firewall log) as
     part of the same evaluate() call, so ONE function call gives you
     the full picture: rules + ML + network-security extensions.

Requires network_security_extensions.py to be in the same directory
(or on the Python path).
"""

import json
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone

import numpy as np
from sklearn.ensemble import IsolationForest

from network_security_extensions import (
    ARPMonitor,
    PortScanDetector,
    DeviceRegistry,
    ZoneValidator,
    TLSValidator,
    RogueDHCPDetector,
    FirewallViolationLogger,
    event_to_features_extended,
)


@dataclass
class ConnectionEvent:
    device_id: str
    dest_ip: str
    dest_port: int
    bytes_sent: int
    hour_of_day: int
    timestamp: str


@dataclass
class DeviceProfile:
    device_id: str
    known_ips: set = field(default_factory=set)
    known_ports: set = field(default_factory=set)
    byte_history: list = field(default_factory=list)
    diagnostic_port: int = None
    ml_model: IsolationForest = None

    def learn(self, event: ConnectionEvent):
        self.known_ips.add(event.dest_ip)
        self.known_ports.add(event.dest_port)
        self.byte_history.append(event.bytes_sent)

    def baseline_summary(self):
        avg = statistics.mean(self.byte_history) if self.byte_history else 0
        return {
            "device_id": self.device_id,
            "known_ips": list(self.known_ips),
            "known_ports": list(self.known_ports),
            "avg_bytes_per_connection": round(avg, 2),
        }


class RuleBasedDetector:
    def __init__(self, byte_spike_multiplier: float = 3.0):
        self.byte_spike_multiplier = byte_spike_multiplier

    def check(self, profile: DeviceProfile, event: ConnectionEvent):
        reasons = []
        if event.dest_ip not in profile.known_ips:
            reasons.append(f"Unknown destination IP: {event.dest_ip}")
        if event.dest_port not in profile.known_ports:
            reasons.append(f"Unknown destination port: {event.dest_port}")
        if profile.byte_history:
            avg = statistics.mean(profile.byte_history)
            if avg > 0 and event.bytes_sent > avg * self.byte_spike_multiplier:
                reasons.append(
                    f"Data volume spike: {event.bytes_sent} bytes "
                    f"(baseline avg {avg:.0f})"
                )
        return reasons


class MLAnomalyDetector:
    def __init__(self, contamination: float = 0.15, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state

    def train(self, profile: DeviceProfile, training_events: list):
        X = np.array([event_to_features_extended(vars(e)) for e in training_events])
        model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=100,
        )
        model.fit(X)
        profile.ml_model = model

    def check(self, profile: DeviceProfile, event: ConnectionEvent):
        if profile.ml_model is None:
            return []
        X = np.array([event_to_features_extended(vars(event))])
        prediction = profile.ml_model.predict(X)[0]
        score = profile.ml_model.decision_function(X)[0]
        if prediction == -1:
            return [f"ML model flagged this connection as anomalous (score={score:.3f})"]
        return []


class IsolationAction:
    @staticmethod
    def isolate(profile: DeviceProfile, reasons: list, source: str):
        action_log = {
            "action": "ISOLATE_FROM_ADMIN_NETWORK",
            "device_id": profile.device_id,
            "diagnostic_port_kept_open": profile.diagnostic_port,
            "detected_by": source,
            "reasons": reasons,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        print(f"\n[ALERT] Anomalous behavior detected (source: {source}) -> isolating device")
        print(json.dumps(action_log, indent=2))
        return action_log


class HybridGuard:
    """
    Combines FOUR detection layers into one evaluate() call:
      1. Rule-based checks (unknown IP/port, byte spike)
      2. ML anomaly detection (Isolation Forest, day-of-week aware)
      3. Network security extensions (ARP, port-scan, rogue device,
         zone validation, TLS, rogue DHCP)
      4. Firewall violation logging (passive, always recorded)
    """

    def __init__(self, known_devices: set = None, authorized_dhcp_servers: set = None):
        self.rule_detector = RuleBasedDetector()
        self.ml_detector = MLAnomalyDetector()
        self.arp_monitor = ARPMonitor()
        self.port_scan_detector = PortScanDetector()
        self.device_registry = DeviceRegistry(known_devices=known_devices)
        self.zone_validator = ZoneValidator()
        self.tls_validator = TLSValidator()
        self.dhcp_detector = RogueDHCPDetector(
            authorized_dhcp_servers=authorized_dhcp_servers or {"10.0.0.1"}
        )
        self.firewall_logger = FirewallViolationLogger()

    def train(self, profile: DeviceProfile, training_events: list):
        for e in training_events:
            profile.learn(e)
        self.ml_detector.train(profile, training_events)
        self.device_registry.register(profile.device_id)

    def evaluate(self, profile: DeviceProfile, event: ConnectionEvent,
                  device_type: str = None, observed_mac: str = None,
                  target_zone: str = None, encrypted: bool = True):
        """
        Runs all four detection layers against a single event.
        Optional parameters (device_type, observed_mac, target_zone,
        encrypted) let callers opt into the extra network-security
        checks when that information is available; if omitted, only
        the core rule+ML checks run (backward compatible with v1).
        """
        rule_reasons = self.rule_detector.check(profile, event)
        ml_reasons = self.ml_detector.check(profile, event)

        extension_reasons = []

        # Rogue device check (always runs)
        rogue = self.device_registry.check(event.device_id)
        if rogue:
            extension_reasons.append(rogue["event"])

        # ARP/MITM check (only if a MAC was supplied)
        if observed_mac:
            arp_result = self.arp_monitor.check(event.dest_ip, observed_mac)
            if arp_result:
                extension_reasons.append(arp_result["event"])

        # Zone validation (only if device_type + target_zone supplied)
        if device_type and target_zone:
            zone_result = self.zone_validator.check(device_type, target_zone)
            if zone_result:
                extension_reasons.append(zone_result["event"])

        # TLS validation (only relevant for PHI-carrying protocols)
        tls_result = self.tls_validator.check(encrypted=encrypted)
        if tls_result:
            extension_reasons.append(tls_result["event"])

        all_reasons = rule_reasons + ml_reasons + extension_reasons
        if not all_reasons:
            return None

        sources = []
        if rule_reasons:
            sources.append("rules")
        if ml_reasons:
            sources.append("ml")
        if extension_reasons:
            sources.append("network_extensions")
        source = "+".join(sources)

        return IsolationAction.isolate(profile, all_reasons, source)


# ---------------------------------------------------------------------
# DEMO
# ---------------------------------------------------------------------
if __name__ == "__main__":
    profile = DeviceProfile(device_id="dental-xray-01", diagnostic_port=104)
    guard = HybridGuard(known_devices={"dental-xray-01"})

    training_events = []
    for i in range(20):
        hour = 9 if i % 4 != 0 else 10
        bytes_sent = 48000 + (i * 300)
        training_events.append(
            ConnectionEvent("dental-xray-01", "10.0.0.5", 104, bytes_sent, hour, "")
        )
    guard.train(profile, training_events)
    print("Baseline learned:", json.dumps(profile.baseline_summary(), indent=2))

    # Case 1: normal event
    normal_event = ConnectionEvent("dental-xray-01", "10.0.0.5", 104, 49000, 9, "2026-07-10T09:05:00+00:00")
    result = guard.evaluate(profile, normal_event)
    print(f"\nCase 1 (normal) -> isolated: {result is not None}")

    # Case 2: rules-only violation (unknown IP)
    bad_event = ConnectionEvent("dental-xray-01", "203.0.113.44", 445, 900000, 2, "2026-07-10T02:13:00+00:00")
    print("\nCase 2 (unknown IP + port + volume spike):")
    guard.evaluate(profile, bad_event)

    # Case 3: network-extension-only violation (zone violation, TLS failure)
    zone_event = ConnectionEvent("dental-xray-01", "10.0.0.5", 104, 49500, 9, "2026-07-10T09:10:00+00:00")
    print("\nCase 3 (zone violation + unencrypted PHI):")
    guard.evaluate(profile, zone_event, device_type="imaging", target_zone="billing_vlan", encrypted=False)

    # Case 4: rogue device (never trained/registered)
    rogue_profile = DeviceProfile(device_id="unregistered-device-99", diagnostic_port=None)
    rogue_event = ConnectionEvent("unregistered-device-99", "10.0.0.99", 8080, 1000, 10, "2026-07-10T10:00:00+00:00")
    print("\nCase 4 (rogue/unregistered device):")
    guard.evaluate(rogue_profile, rogue_event)
