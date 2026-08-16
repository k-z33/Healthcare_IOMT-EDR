# Healthcare IoMT AI-Driven EDR Platform

An AI-driven Endpoint Detection and Response (EDR) system purpose-built for hospital IoMT environments — infusion pumps, ventilators, patient monitors, imaging devices, and pharmacy dispensing cabinets.

Built as the capstone project for the **EduQual Level 6 AI Operations Diploma (Al Nafi International College)** by Kainat Zahra, BDS.

---

## Why this project exists

Medical devices are frequently unpatchable, run legacy protocols, and directly affect patient safety when compromised — yet most EDR tooling is built for corporate IT, not clinical environments. This project applies SOC-grade detection, machine-learning anomaly scoring, and automated incident response to the IoMT threat model specifically, with HIPAA/NIST/HITRUST compliance mapping built in from the start.

## Architecture

```
Ubuntu Endpoint (simulated/real IoMT device traffic)
        │
        ▼
Wazuh Manager (Docker) ── 35 custom detection rules
        │                  (100200-100226, 100234-100241)
        ▼
alerts.json ── read directly by live_edr.py
        │        (Wazuh REST API returned empty in testing;
        │         direct file read is the reliable path)
        ▼
live_edr.py
   ├── ML scoring (Isolation Forest + Random Forest)
   ├── Threat-intel enrichment (AbuseIPDB + VirusTotal)
   ├── auto_contain.py (patient-safety-weighted containment)
   ├── thehive_integration.py → TheHive case auto-created
   ├── chain_of_custody.py → evidence hash-tracked
   ├── metrics.py → MTTD/MTTR logged
   └── Velociraptor → forensic collection tied to the case
        │
        ▼
OpenSearch/Kibana Dashboards (iomt-alerts* index)
+ Sigma detection-as-code layer (32 rules, SIEM-agnostic)
+ Automated compliance report (NIST/HIPAA/HITRUST, HTML)
```

## Key capabilities

- **35 custom Wazuh detection rules**, MITRE ATT&CK / ATT&CK-for-ICS mapped, covering network anomalies, protocol/device-integrity abuse, patient-safety-weighted device categories, and DICOM/HL7-specific attacks
- **Sigma detection-as-code layer** — the same 35 detections re-expressed in vendor-neutral Sigma format (32 files), each with a CVSS v3.1 score, HIPAA citation, and MITRE tag, convertible to Splunk SPL / Microsoft Sentinel KQL / OpenSearch queries
- **ML anomaly scoring** — Isolation Forest (unsupervised) + Random Forest (supervised), evaluated against a labeled test set (see `model_evaluation.py`)
- **Patient-safety-weighted auto-containment** — infusion pumps and ventilators treated with the highest urgency given direct dosing/life-support risk
- **Automatic SOC case creation** (TheHive) tied to **Velociraptor** forensic collection
- **Chain-of-custody tracking** — SHA-256 hash verification at collection, transfer, and analysis stages; tamper is detected automatically
- **SOC response-time KPIs** — MTTD, MTTC (mean time to case), MTTR tracked per incident
- **Lightweight threat-intel enrichment** (AbuseIPDB + VirusTotal) — same function as a Cortex+MISP deployment, without the infra weight that blocked Cortex on this lab's arm64 host
- **HIPAA/NIST CSF/HITRUST-mapped compliance reporting**, auto-generated as HTML

## Quick start

```bash
git clone <this-repo>
cd healthcare-edr

# Bring up the Docker stack (Wazuh + TheHive + Cassandra)
docker compose up -d

# On the endpoint, simulate an attack
python3 simulate_medical_device.py --attack firmware_tampering

# Watch the pipeline
python3 live_edr.py                 # live alert stream + ML scoring
# → check TheHive UI for the auto-created case
# → check Kibana (iomt-alerts* index) for the dashboard

# After a demo run, check response-time KPIs
python3 metrics.py report

# Evaluate ML model performance
python3 model_evaluation.py --json edr_predictions.jsonl
```

## Repository structure

```
detection-rules/
  wazuh-native/        # iomt_custom_rules.xml, iomt_network_security_rules.xml
  sigma/                # 32 Sigma detection-as-code rules
  spl/  kql/             # Splunk / Sentinel conversions
scripts/
  live_edr.py
  auto_contain.py
  thehive_integration.py
  chain_of_custody.py
  metrics.py
  threat_intel_enrichment.py
  model_evaluation.py
docs/
  IR_Playbook.md
  EDR_Architecture_Status.docx
```

## Known limitations (documented, not hidden)

- **Cortex** was evaluated but not integrated — an arm64/amd64 Docker image incompatibility blocked deployment on the Mac SOC host. Threat-intel enrichment is handled via lightweight direct API calls instead (see above).
- **MISP** was ruled out for the same host's RAM constraints; the same reasoning applies.
- Live traffic in this lab is simulated (`simulate_medical_device.py`) rather than real clinical device traffic, for obvious safety/legal reasons.

## License / Contact

Kainat Zahra — kainat.zahra513@gmail.com — [LinkedIn](https://linkedin.com/in/dr-kainat-zahra-41a148304)
