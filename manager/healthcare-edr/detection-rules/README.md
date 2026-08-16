# Detection-as-Code: Sigma <-> Wazuh Rule Mapping

Auto-generated. 32 Sigma rule files, covering 35 Wazuh rule IDs (100200-100241).

| Wazuh Rule ID | Sigma File | Title | Severity | MITRE |
|---|---|---|---|---|
| 100201 | `unknown_destination_ip.yml` | Device Connection to Unknown Destination IP | medium | T1071 |
| 100202 | `unexpected_port_connection.yml` | Device Connection on Unexpected Port | medium | T1571 |
| 100203 | `data_volume_spike.yml` | Device Data Volume Spike | medium | T1030 |
| 100204 | `device_activity_off_hours.yml` | Device Activity Outside Normal Operating Hours | low | - |
| 100205 | `device_flooding_dos.yml` | Abnormally Frequent Device Connections (Flooding/DoS) | medium | T0814 |
| 100206 | `unauthorized_firmware_update.yml` | Unauthorized Firmware or Update Request | critical | T1195 |
| 100207 | `legacy_insecure_protocol.yml` | Legacy or Insecure Protocol Usage | high | T1552 |
| 100208 | `default_credential_login.yml` | Default or Weak Credential Login | high | T1078 |
| 100211 | `replay_attack_suspected.yml` | Possible Replay Attack Detected | medium | T1499 |
| 100212 | `unencrypted_phi_transmission.yml` | Unencrypted PHI-Carrying Protocol Transmission | medium | T1040 |
| 100213 | `time_sync_anomaly.yml` | Device Clock or Time-Sync Anomaly | medium | T1070 |
| 100214 | `lateral_movement_segment.yml` | Lateral Movement to Admin or Billing Segment | high | T1021 |
| 100217 | `patient_monitor_anomaly.yml` | Patient Monitor Anomalous Activity | high | T0836 |
| 100218 | `imaging_device_anomaly.yml` | Imaging Device Anomalous Activity | medium | - |
| 100219 | `pharmacy_dispensing_anomaly.yml` | Pharmacy Dispensing Cabinet Anomalous Activity | high | T1078 |
| 100220 | `multi_anomaly_isolation_trigger.yml` | Multiple Anomaly Indicators on Same Device (Isolation Trigger) | critical | - |
| 100222 | `hl7_message_tampering.yml` | HL7 Message Tampering Detected | high | T1565 |
| 100223 | `unauthorized_device_reboot.yml` | Unauthorized Device Reboot | high | T0816 |
| 100225 | `network_reconnaissance_scan.yml` | Network Reconnaissance or Scanning Activity | medium | T1046 |
| 100234 | `arp_spoofing_mitm.yml` | ARP Spoofing / MITM Detected | high | T1557 |
| 100235 | `port_scan_detected.yml` | Port Scan Detected | high | T1046 |
| 100237 | `network_segmentation_violation.yml` | Network Segmentation (Zone) Violation | high | T1021 |
| 100238 | `tls_certificate_validation_failure.yml` | TLS/Certificate Validation Failure | medium | T1040 |
| 100239 | `rogue_dhcp_server.yml` | Rogue DHCP Server Detected | high | T1557 |
| 100240 | `firewall_acl_violation.yml` | Firewall/ACL Violation (Blocked Attempt) | low | T1046 |
| 100241 | `repeated_firewall_violations.yml` | Repeated Firewall Violations (Active Reconnaissance) | high | T1595 |
| - | `device_impersonation.yml` | Possible Medical Device Impersonation Detected | high | T1557 |
| - | `dicom_exfiltration.yml` | Unauthorized DICOM Image Transfer Detected | high | T1537 |
| - | `infusion_pump_config_change.yml` | Unauthorized Infusion Pump Configuration Change | critical | T0836 |
| - | `repeated_failed_authentication.yml` | Repeated Failed Authentication on Medical Device | medium | T1110 |
| - | `rogue_device_detected.yml` | Rogue or Unregistered Device Detected on Clinical Network | high | T1200 |
| - | `ventilator_anomalous_activity.yml` | Ventilator Anomalous Activity Detected | critical | T0836 |
