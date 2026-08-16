#!/bin/bash
# ============================================================
# HEALTHCARE-EXTENDED EDR — IoMT ATTACK SIMULATION (COLOR)
# Target Agent : ip-172-31-27-110  |  Infra: Docker-Wazuh
#
# DETECTION LAYERS IN THIS DEMO (3 distinct layers — do not confuse):
#
#   [HIDS / RULE-ENGINE]  Categories 1-4. Simulated device telemetry
#                          (simulate_medical_device.py + inline JSON)
#                          parsed by Wazuh's own custom decoders/rules
#                          (iomt_custom_rules.xml, iomt_network_security_
#                          rules.xml). DETECTION ONLY — this layer does
#                          not touch real network packets.
#
#   [ACTIVE-RESPONSE/IPS]  Triggered automatically BY the HIDS layer
#                          above when severity crosses a threshold —
#                          auto_contain.py performs the actual isolation
#                          action (device containment). This is the only
#                          layer in this demo that PREVENTS/BLOCKS, not
#                          just detects — hence "IPS-like".
#
#   [NIDS / SURICATA]      Category 5. Real Suricata engine doing live
#                          packet inspection on the wire -> eve.json ->
#                          Wazuh tail. DETECTION ONLY, no blocking is
#                          configured (Suricata is running in IDS/af-
#                          packet mode here, not inline IPS mode).
# ============================================================

set -e
LOG="/var/log/iomt/medical_device.log"

# ── Colors ───────────────────────────────────────────────────
RESET='\033[0m'
BOLD='\033[1m'
GREY='\033[90m'
CYAN='\033[96m'      # DEVICE-BEHAVIOR
RED='\033[91m'       # PATIENT-SAFETY
YELLOW='\033[93m'    # DATA-INTEGRITY / CORRELATION
PURPLE='\033[95m'    # NETWORK-SECURITY
GREEN='\033[92m'     # success / summary

TOTAL=25
STEP=0

section() {
  # $1=color $2=title $3=layer-tag (e.g. "[HIDS / RULE-ENGINE — detection only]")
  local color="$1"; local title="$2"; local layer="$3"
  echo ""
  printf "${color}${BOLD}════════════════════════════════════════════════════════════${RESET}\n"
  printf "${color}${BOLD}  %s${RESET}\n" "$title"
  if [ -n "$layer" ]; then
    printf "${GREY}  Layer: %s${RESET}\n" "$layer"
  fi
  printf "${color}${BOLD}════════════════════════════════════════════════════════════${RESET}\n"
}

# $1=rule $2=color $3=CAT $4=Attack Name  ...rest = args to simulate_medical_device.py
trigger() {
  local rule="$1"; local color="$2"; local cat="$3"; local name="$4"; shift 4
  STEP=$((STEP+1))
  printf "${color}▶ [%02d/%d] [%s] Rule %s${RESET} — ${BOLD}%s${RESET}\n" "$STEP" "$TOTAL" "$cat" "$rule" "$name"

  local out
  out=$(python3 simulate_medical_device.py "$@" 2>&1)
  local count
  count=$(printf '%s\n' "$out" | grep -c '^Logged:' || true)

  if [ "$count" -gt 1 ]; then
    printf '%s\n' "$out" | tail -1 | sed 's/^/    /'
    printf "  ${GREEN}✓ %d events injected${RESET}\n" "$count"
  elif [ "$count" -eq 1 ]; then
    printf '%s\n' "$out" | sed 's/^Logged: /    /'
    printf "  ${GREEN}✓ logged${RESET}\n"
  else
    printf '%s\n' "$out" | sed 's/^/    /'
  fi
  sleep 1
}

# $1=rule $2=color $3=CAT $4=Attack Name — for the inline python -c log_event blocks
log_header() {
  local rule="$1"; local color="$2"; local cat="$3"; local name="$4"
  STEP=$((STEP+1))
  printf "${color}▶ [%02d] [%s] Rule %s${RESET} — ${BOLD}%s${RESET}\n" "$STEP" "$cat" "$rule" "$name"
}

echo ""
printf "${BOLD}🏥 HEALTHCARE-EXTENDED EDR: IoMT ATTACK SIMULATION 🏥${RESET}\n"
printf "${GREY}Target Agent: ip-172-31-27-110 | Infra: Docker-Wazuh${RESET}\n"
printf "${GREY}Legend: ${CYAN}■${RESET} device-behavior  ${RED}■${RESET} patient-safety  ${YELLOW}■${RESET} data-integrity  ${PURPLE}■${RESET} network-security\n"
sleep 1

# ═══════════════════════════════════════════════════════════
# CATEGORY 1: DEVICE-BEHAVIOR ANOMALIES (100201–100214)
# ═══════════════════════════════════════════════════════════
section "$CYAN" "📡 CATEGORY 1: DEVICE-BEHAVIOR ANOMALIES  (Rules 100201–100214)"

trigger 100201 "$CYAN" DEVICE-BEHAVIOR "Unknown Destination IP" \
    --device dental-xray-01 --mode unknown_ip --count 1

trigger 100202 "$CYAN" DEVICE-BEHAVIOR "Unexpected Port" \
    --device dental-xray-01 --mode unknown_port --count 1

trigger 100203 "$CYAN" DEVICE-BEHAVIOR "Data Volume Spike" \
    --device dental-xray-01 --mode volume_spike --count 1

trigger 100204 "$CYAN" DEVICE-BEHAVIOR "Off-Hours Access" \
    --device dental-xray-01 --mode odd_hour --count 1

trigger 100205 "$CYAN" DEVICE-BEHAVIOR "Flooding (Rapid Connections)" \
    --device dental-xray-01 --mode flooding --count 25 --interval 0.1

trigger 100206 "$CYAN" DEVICE-BEHAVIOR "Unauthorized Firmware Update Attempt" \
    --device infusion-pump-03 --mode firmware_attempt --count 1

trigger 100207 "$CYAN" DEVICE-BEHAVIOR "Legacy/Plaintext Protocol Used" \
    --device pharmacy-cabinet-01 --mode legacy_protocol --count 1

trigger 100208 "$CYAN" DEVICE-BEHAVIOR "Default Credential Login" \
    --device pharmacy-cabinet-01 --mode default_credential --count 1

trigger 100209 "$CYAN" DEVICE-BEHAVIOR "Repeated Failed Authentication (Brute Force)" \
    --device pharmacy-cabinet-01 --mode auth_failed --count 6 --interval 2

trigger 100210 "$CYAN" DEVICE-BEHAVIOR "Device Impersonation (MAC/IP Mismatch)" \
    --device dental-xray-01 --mode mac_ip_mismatch --count 1

trigger 100211 "$CYAN" DEVICE-BEHAVIOR "Replay Attack Suspected" \
    --device patient-monitor-07 --mode replay_suspected --count 1

trigger 100212 "$CYAN" DEVICE-BEHAVIOR "Unencrypted PHI Transmission" \
    --device dental-xray-01 --mode unencrypted_phi --count 1

trigger 100213 "$CYAN" DEVICE-BEHAVIOR "Time Sync / Clock Drift Anomaly" \
    --device ventilator-02 --mode time_sync_anomaly --count 1

trigger 100214 "$CYAN" DEVICE-BEHAVIOR "Cross-Segment (VLAN) Access" \
    --device dental-xray-01 --mode cross_segment --count 1

# ═══════════════════════════════════════════════════════════
# CATEGORY 2: PATIENT-SAFETY DEVICE ALERTS (100215–100219)
# ═══════════════════════════════════════════════════════════
section "$RED" "🚨 CATEGORY 2: PATIENT-SAFETY DEVICE ALERTS  (Rules 100215–100219)"

trigger 100215 "$RED" PATIENT-SAFETY "Infusion Pump Anomaly (Patient Dosing Risk)" \
    --device infusion-pump-03 --mode unknown_ip --count 1

trigger 100216 "$RED" PATIENT-SAFETY "Ventilator Anomaly (Life-Support Risk)" \
    --device ventilator-02 --mode volume_spike --count 1

trigger 100217 "$RED" PATIENT-SAFETY "Patient Monitor Anomaly (Vitals Integrity)" \
    --device patient-monitor-07 --mode unknown_port --count 1

trigger 100218 "$RED" PATIENT-SAFETY "Imaging Device Anomaly (DICOM Tampering Risk)" \
    --device dental-xray-01 --mode volume_spike --count 1

trigger 100219 "$RED" PATIENT-SAFETY "Pharmacy Dispensing Anomaly (Diversion Risk)" \
    --device pharmacy-cabinet-01 --mode unknown_ip --count 1

# ═══════════════════════════════════════════════════════════
# CATEGORY 3: CORRELATION & DATA-INTEGRITY ALERTS (100220–100225)
# ═══════════════════════════════════════════════════════════
section "$YELLOW" "🔗 CATEGORY 3: CORRELATION & DATA-INTEGRITY ALERTS  (Rules 100220–100225)"

STEP=$((STEP+1))
printf "${YELLOW}▶ [%02d/%d] [CORRELATION] Rule 100220${RESET} — ${BOLD}Multi-Indicator Correlation (Device Isolation)${RESET}\n" "$STEP" "$TOTAL"
python3 simulate_medical_device.py --device dental-xray-01 --mode unknown_ip --count 1 > /dev/null 2>&1
python3 simulate_medical_device.py --device dental-xray-01 --mode volume_spike --count 1 > /dev/null 2>&1
printf "  ${GREEN}✓ 2 correlated events injected${RESET}\n"
sleep 1

trigger 100221 "$YELLOW" DATA-INTEGRITY "DICOM Exfiltration (Unauthorized C-STORE)" \
    --device dental-xray-01 --mode dicom_exfiltration --count 1

trigger 100222 "$YELLOW" DATA-INTEGRITY "HL7 Message Tampering" \
    --device patient-monitor-07 --mode hl7_tampering --count 1

trigger 100223 "$YELLOW" DATA-INTEGRITY "Unauthorized Device Reboot" \
    --device ventilator-02 --mode device_reboot --count 1

trigger 100224 "$YELLOW" DATA-INTEGRITY "Unauthorized Config Change" \
    --device infusion-pump-03 --mode config_change --count 1

trigger 100225 "$YELLOW" DATA-INTEGRITY "Network Scan Detected" \
    --device dental-xray-01 --mode network_scan --count 1

echo ""
printf "${GREEN}${BOLD}🎯 ALL 25 IoMT CUSTOM ALERTS INJECTED INTO TELEMETRY STREAM!${RESET}\n"
sleep 1

# ═══════════════════════════════════════════════════════════
# CATEGORY 4: NETWORK-SECURITY EXTENSIONS (100234–100241)
# ═══════════════════════════════════════════════════════════
section "$PURPLE" "🔒 CATEGORY 4: NETWORK-SECURITY EXTENSIONS  (Rules 100234–100241)"

log_header 100234 "$PURPLE" NETWORK-SECURITY "ARP Spoofing / MITM Detected"
python3 -c "
import json, datetime
event = {
    'event': 'arp_spoofing_suspected',
    'device_id': 'dental-xray-01',
    'ip': '10.0.0.5',
    'expected_mac': 'AA:BB:CC:00:11:22',
    'observed_mac': 'DE:AD:BE:EF:00:99',
    'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
with open('$LOG', 'a') as f:
    f.write(json.dumps(event) + '\n')
print('    logged:', event['event'])
"
sleep 1

log_header 100235 "$PURPLE" NETWORK-SECURITY "Port Scan Detected"
python3 -c "
import json, datetime
event = {
    'event': 'port_scan_detected',
    'device_id': 'unregistered-scanner',
    'source_ip': '10.0.0.99',
    'distinct_ports_touched': 6,
    'window_seconds': 30,
    'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
with open('$LOG', 'a') as f:
    f.write(json.dumps(event) + '\n')
print('    logged:', event['event'])
"
sleep 1

log_header 100236 "$PURPLE" NETWORK-SECURITY "Rogue Device Detected"
python3 -c "
import json, datetime
event = {
    'event': 'rogue_device_detected',
    'device_id': 'unregistered-device-99',
    'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
with open('$LOG', 'a') as f:
    f.write(json.dumps(event) + '\n')
print('    logged:', event['event'])
"
sleep 1

log_header 100237 "$PURPLE" NETWORK-SECURITY "Network Segmentation Violation"
python3 -c "
import json, datetime
event = {
    'event': 'zone_violation',
    'device_id': 'infusion-pump-03',
    'device_type': 'infusion_pump',
    'target_zone': 'billing_vlan',
    'allowed_zones': ['clinical_vlan'],
    'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
with open('$LOG', 'a') as f:
    f.write(json.dumps(event) + '\n')
print('    logged:', event['event'])
"
sleep 1

log_header 100238 "$PURPLE" NETWORK-SECURITY "TLS/Certificate Validation Failed"
python3 -c "
import json, datetime
event = {
    'event': 'tls_validation_failed',
    'device_id': 'patient-monitor-07',
    'issues': ['unencrypted_channel', 'expired_certificate'],
    'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
with open('$LOG', 'a') as f:
    f.write(json.dumps(event) + '\n')
print('    logged:', event['event'])
"
sleep 1

log_header 100239 "$PURPLE" NETWORK-SECURITY "Rogue DHCP Server Detected"
python3 -c "
import json, datetime
event = {
    'event': 'rogue_dhcp_detected',
    'device_id': 'dental-xray-01',
    'dhcp_server_ip': '10.0.0.250',
    'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
with open('$LOG', 'a') as f:
    f.write(json.dumps(event) + '\n')
print('    logged:', event['event'])
"
sleep 1

log_header 100240 "$PURPLE" NETWORK-SECURITY "Firewall Violation (Blocked Attempt)"
python3 -c "
import json, datetime
event = {
    'event': 'firewall_violation',
    'device_id': 'ventilator-02',
    'attempted_dest': '203.0.113.44',
    'attempted_port': 445,
    'action': 'blocked',
    'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
with open('$LOG', 'a') as f:
    f.write(json.dumps(event) + '\n')
print('    logged:', event['event'])
"
sleep 1

log_header 100241 "$PURPLE" NETWORK-SECURITY "Repeated Firewall Violations (Reconnaissance Escalation)"
for i in 1 2 3 4 5; do
  python3 -c "
import json, datetime
event = {
    'event': 'firewall_violation',
    'device_id': 'ventilator-02',
    'attempted_dest': '203.0.113.44',
    'attempted_port': 445,
    'action': 'blocked',
    'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
with open('$LOG', 'a') as f:
    f.write(json.dumps(event) + '\n')
"
  sleep 0.3
done
printf "  ${GREEN}✓ 5/5 repeated violations injected${RESET}\n"

echo ""
printf "${GREEN}${BOLD}🎯 8/8 NETWORK-SECURITY RULES INJECTED (100234–100241)!${RESET}\n"

# ═══════════════════════════════════════════════════════════
# CATEGORY 5: SURICATA / NETWORK-IDS (Live Traffic-Based)
# Real network traffic that trips Suricata's own signatures —
# NOT log-injection like the categories above. Requires Suricata
# to be installed + running (af-packet on the live interface) and
# Wazuh reading /var/log/suricata/eve.json.
# ═══════════════════════════════════════════════════════════
ORANGE='\033[38;5;208m'   # SURICATA category color

section "$ORANGE" "🛰️  CATEGORY 5: SURICATA / NETWORK-IDS  (live traffic triggers)"

STEP=$((STEP+1))
printf "${ORANGE}▶ [%02d] [SURICATA] GPL ATTACK_RESPONSE${RESET} — ${BOLD}id check returned root (testmyids.com)${RESET}\n" "$STEP"
curl -s -m 5 http://testmyids.com > /dev/null
printf "  ${GREEN}✓ request sent — check eve.json / live_edr_iomt.py for [SURICATA] tag${RESET}\n"
sleep 2

STEP=$((STEP+1))
printf "${ORANGE}▶ [%02d] [SURICATA] ET SCAN${RESET} — ${BOLD}Nmap scan signature (self-scan, own host only)${RESET}\n" "$STEP"
if command -v nmap >/dev/null 2>&1; then
  nmap -sS -F localhost > /dev/null 2>&1
  printf "  ${GREEN}✓ self-scan sent — check eve.json / live_edr_iomt.py for [SURICATA] tag${RESET}\n"
else
  printf "  ${YELLOW}⚠ nmap not installed — skipping (sudo apt install nmap -y to enable)${RESET}\n"
fi
sleep 2

printf "${GREY}Note: only testmyids.com (built by Emerging Threats for this exact purpose)\n"
printf "and self-scans against your own host are used here — no external targets.${RESET}\n"

# ═══════════════════════════════════════════════════════════
# STANDALONE MODULE-LEVEL DEMO (no Wazuh trigger)
# ═══════════════════════════════════════════════════════════
section "$GREY" "🧪 STANDALONE VALIDATION: network_security_extensions.py (module-level only)"
if [ -f "network_security_extensions.py" ]; then
  python3 network_security_extensions.py
else
  printf "  ${YELLOW}⚠ network_security_extensions.py not found in $(pwd) — skipping${RESET}\n"
  printf "  ${GREY}Run this script from the folder that contains it, e.g. cd ~/healthcare-edr${RESET}\n"
fi

echo ""
printf "${GREEN}${BOLD}🎯 DEMO COMPLETE — 25 IoMT rules + 8 network-security concepts${RESET}\n"
echo ""
