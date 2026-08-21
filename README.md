# 🏥 Healthcare IoMT AI-Driven XDR Platform

**Enterprise-grade Endpoint Detection & Response, purpose-built for hospital IoMT networks**

[![Status](https://img.shields.io/badge/status-complete-brightgreen)]()
[![Focus](https://img.shields.io/badge/focus-Healthcare%20Cybersecurity-blue)]()
[![Compliance](https://img.shields.io/badge/compliance-HIPAA%20%7C%20HITRUST%20%7C%20NIST%20%7C%20ISO27001-orange)]()
[![Cloud](https://img.shields.io/badge/cloud-AWS%20(3--node)-yellow)]()

**Author:** Dr. Kainat Zahra Khalil, BDS · EduQual Level 6 Diploma in AI Operations (Al Nafi — Enterprise Cyber Defense track)
**Repo:** [github.com/k-z33/Healthcare_IOMT-EDR](https://github.com/k-z33/Healthcare_IOMT-EDR)
**Built:** August 2026 · **Status:** Complete (limitations documented, not hidden)

---

## 🎯 What This Project Is

A full **Security Operations Center (SOC) pipeline**, engineered end-to-end and self-hosted across a **3-node AWS lab**, that detects, investigates, and contains cyberattacks against **hospital IoMT devices** — infusion pumps, ventilators, patient monitors, imaging systems (DICOM), and pharmacy dispensing cabinets.

Unlike a generic EDR demo, every design decision here answers one question: **"What happens to the patient if this control fires wrong?"** That question — asked by someone with a clinical background, not just an engineering one — shapes the containment logic, the compliance mapping, and the detection priorities throughout.

---

## 👩‍💻 Skills Demonstrated 

| Domain | What was actually built |
|---|---|
| **SIEM Engineering** | Wazuh manager/agent deployment, custom XML detection rules, log pipeline tuning |
| **Detection Engineering** | 32+ Sigma rules authored from scratch, converted to KQL + SPL + Wazuh-native, MITRE ATT&CK-tagged |
| **SOC Case Management** | TheHive + Cortex integration; automated case creation from Wazuh alerts |
| **Machine Learning for Security** | Trained Isolation Forest (unsupervised anomaly) + Random Forest (supervised classifier) on IoMT traffic; ML-overlay severity scoring with human-review audit trail |
| **Incident Response / Orchestration** | Python-based auto-containment engine with **patient-safety-aware decision logic** (escalate vs. isolate) |
| **Digital Forensics (DFIR)** | Velociraptor deployment, TShark packet capture, Volatility3 memory forensics, PHI/credential leak scanning in pcaps |
| **Threat Intelligence** | MISP integration, MITRE ATT&CK + ATT&CK for ICS Navigator layer generation |
| **Governance, Risk & Compliance (GRC)** | Live compliance engines mapping real alerts to HIPAA Security Rule, HITRUST CSF, NIST CSF, PCI-DSS, ISO 27001 |
| **Cloud Security (AWS)** | 3-instance VPC architecture, Security Group hardening, self-performed security audit with 13 tracked findings |
| **Secure SDLC** | Git secrets hygiene (private keys/TLS certs stripped pre-commit), `.gitignore` discipline, credential rotation to env vars |
| **Malware/Threat Detection** | Custom YARA rules for healthcare-relevant indicators |
| **Domain Expertise** | Clinical device risk classification (life-supporting vs. non-critical), HL7/DICOM protocol-aware detections |

---
## 🏗️ Architecture — 3-Node AWS Lab

| Role | Private IP | Purpose | Key Software |
|---|---|---|---|
| **Agent** | `172.31.27.110` | Simulated IoMT / clinical endpoint | Wazuh agent, Suricata, Velociraptor client, attack + capture scripts |
| **Manager** | `172.31.44.154` | SOC server / orchestrator | Wazuh manager, `live_edr_iomt.py`, ML models, TheHive, Cortex, compliance engine |
| **Forensics** | `172.31.33.186` | DFIR node | Velociraptor server, TShark, Volatility3, PHI/credential scanner, report indexer |

All nodes share one AWS VPC (private networking only). Agent → Manager over the Wazuh protocol; Manager ↔ Forensics via key-based SSH/SCP for report sync. Security Groups were hardened post-audit — management ports scoped to admin IP + VPC-internal traffic only.

```
Agent (simulated attacks + Wazuh events + pcap capture)
        │
        ▼
Manager — live_edr_iomt.py
   → severity scoring + MITRE ATT&CK + HIPAA mapping
   → ML overlay (Isolation Forest + Random Forest, advisory)
   → patient-safety-aware containment decision
   → TheHive case creation + investigation report
   → compliance generation (HIPAA/HITRUST + NIST/PCI/ISO) + sync
        │
        ▼
Forensics — TShark + Volatility3 → HTML report
   → cleartext PHI / credential exposure scan
   → combined index.html + terminal dashboards
```

## 🩺 Healthcare / IoMT Focus

This is the differentiator: security decisions here are filtered through **clinical risk**, not just IT risk.

| Concern | How the platform addresses it |
|---|---|
| **Patient safety** | Containment logic prefers escalate/monitor over blind isolate when the device class is life-supporting (ventilator, infusion pump) |
| **PHI exposure** | Dedicated pcap cleartext scanner for MRN / SSN / DOB patterns and HTTP Basic Auth / password fields |
| **Clinical protocols** | Purpose-built detections for DICOM exfiltration, HL7 message tampering, pharmacy dispensing anomalies, infusion-pump config changes, ventilator anomalous activity |
| **Vendor / BAA risk** | Device inventory with patch-age and unregistered-device flags, mapped to HIPAA §164.308(b) Business Associate-style obligations |
| **Compliance** | Live HIPAA Security Rule + HITRUST CSF mapping generated directly from real Wazuh alerts, alongside NIST CSF / PCI-DSS / ISO 27001 |

Simulated device classes used in demos: infusion pumps, ventilators, dental/imaging X-ray, pharmacy cabinets, patient monitors.

---

## 🔎 Detection-as-Code (Sigma → KQL / SPL / Wazuh)

**Location:** `manager/healthcare-edr/detection-rules/`

| Format | Path | Coverage |
|---|---|---|
| **Sigma YAML** | `detection-rules/sigma/*.yml` | ~32 hand-written, IoMT-focused rules |
| **KQL** | `detection-rules/kql/*.kql` | Full conversion of every Sigma rule |
| **SPL (Splunk)** | `detection-rules/spl/*.spl` | Full conversion of every Sigma rule |
| **Wazuh-native XML** | `detection-rules/wazuh-native/`, `rules/` | Custom IoMT + network security rule sets |
| **MITRE ATT&CK Navigator** | `sigma/navigator_layer*.json` | Enterprise + ICS heat-map layers |

### Rule Themes Written from Scratch

- `dicom_exfiltration.yml` — imaging data leaving expected paths
- `hl7_message_tampering.yml` — clinical message integrity violations
- `infusion_pump_config_change.yml` — unauthorized therapy parameter changes
- `ventilator_anomalous_activity.yml` — respiratory device anomalies
- `pharmacy_dispensing_anomaly.yml` — dispensing pattern deviation
- `patient_monitor_anomaly.yml` — telemetry/monitoring abuse
- `unencrypted_phi_transmission.yml` — cleartext clinical data in transit
- `legacy_insecure_protocol.yml` — insecure management protocols on clinical devices
- `device_impersonation.yml` / `rogue_device_detected.yml` — identity spoofing on the ward network
- `network_segmentation_violation.yml` / `lateral_movement_segment.yml` — flat-network / cross-segment movement
- `arp_spoofing_mitm.yml` / `rogue_dhcp_server.yml` — local-network attacks against medical VLANs
- Plus: port scan, default credentials, firmware update abuse, unauthorized reboot, time-sync anomaly, TLS validation failure, and more

Rules are MITRE-tagged where mapped. Known gap: partial keyword coverage in one compliance mapper causes some alerts to fall back to `T0000/Unknown` — flagged honestly as a follow-up item, not hidden.

---

## 🧠 Machine Learning Layer

| Model | Type | Role |
|---|---|---|
| **Isolation Forest** | Unsupervised anomaly detection | Flags statistically unusual device/network behavior |
| **Random Forest** | Supervised classifier | Trained on labeled IoMT traffic for severity classification |

- Feature extraction pipeline: `feature_extractor_iomt.py`
- Training scripts: `train_isolation_forest_iomt.py`, `train_random_forest_iomt.py`
- Enrichment at alert time: `ml_enrichment_iomt.py`, `iomt_guard_ml.py`
- **AI governance:** every ML prediction is logged with an audit trail (`ml_audit_logger.py`) — scores are **advisory**, feeding human/SOC decision-making rather than fully automating containment for high-risk devices
- Evaluation: `scripts/model_evaluation.py`, `ml_metrics_report.html`, `ml_test_set_100.csv`

---

## 🧬 Digital Forensics (DFIR)

Runs on the dedicated **Forensics** node, triggered post-incident:

- **Network forensics:** TShark packet capture analysis (`forensics-tools/generate_report.py`)
- **Memory forensics:** Volatility3 process/memory analysis
- **PHI/credential leak detection:** `pcap_phi_credential_check.py` scans captured traffic for MRN/SSN/DOB patterns and exposed credentials
- **Chain of custody:** `scripts/chain_of_custody.py`
- **Reporting:** auto-generated HTML reports (`pretty_forensic.py`, `pretty_phi.py`) indexed via `build_index.sh`

---

## 📋 Compliance & Governance

| Generator | Frameworks | Nature |
|---|---|---|
| `live_complainace_iomt.py` | HIPAA Security Rule, HITRUST CSF, NIST (healthcare-focused) | **Live** — reads real Wazuh alerts, device inventory, EDR metrics |
| `config/compliance_report.py` | NIST CSF, PCI-DSS, ISO 27001 | Real numeric metrics; narrative evidence text is illustrative/template (labeled honestly) |

Both run via `run_compliance_and_sync.sh`, auto-synced to the Forensics node. All compliance HTML uses a consistent visual theme with the forensic reports for clean portfolio screenshots.

---

## 🔐 Security Audit & Hardening (Self-Performed)

A structured security assessment was run against **all three AWS nodes** (13–14 August 2026), followed by remediation and a second-pass Security Group review — validated with live commands on each host, not a paper exercise.

**Outcome: 13 findings tracked · 12 fully remediated · 1 formally accepted lab risk.**

| Severity | Found | Fixed | Accepted |
|---|---|---|---|
| Critical | 5 | 4 | 1 (documented) |
| High | 3 | 3 | 0 |
| Medium/Low | 5 | 5 | 0 |
| **Total** | **13** | **12** | **1** |

### Scope

| Area | Reviewed |
|---|---|
| **Host posture** | Users, sudo, SSH, package hygiene, world-writable paths, sensitive file permissions |
| **Application stack** | Wazuh, TheHive, Cortex, Elasticsearch/OpenSearch, Velociraptor, custom Python EDR code |
| **Secrets in code** | Hardcoded API keys, passwords, `verify=False`, embedded tokens |
| **Network exposure** | AWS Security Groups, bind addresses (0.0.0.0 vs. localhost/VPC), management ports |
| **TLS/crypto** | Certificate verification in clients, indexer SSL material handling |
| **Lab ops risk** | Crash-loops, stale SG rules, leftover admin IPs |

Endpoint scan helpers: [`security-audit-scans/`](security-audit-scans/) — one script per node (`_agent.sh`, `_manager.sh`, `_forensics.sh`) used to re-run local checks after every fix.

### Findings Summary

| # | Severity | Machine | Finding | Status |
|---|---|---|---|---|
| 1 | CRITICAL | Manager | Hardcoded credentials/secrets in source | **FIXED** — moved to env vars, no live keys in repo |
| 2 | CRITICAL | All 3 | Passwordless sudo for default `ubuntu` user (AWS default) | **ACCEPTED RISK** — documented |
| 3 | CRITICAL | Forensics | Elasticsearch/OpenSearch reachable beyond intended scope | **FIXED** — bind + SG restricted |
| 4 | HIGH | Manager | TLS `verify=False` in integration code | **FIXED** — proper cert verification |
| 5 | HIGH | Manager | TheHive/Cortex management interfaces overly exposed | **FIXED** — SG + listen scope tightened |
| 6 | HIGH | Forensics | Velociraptor wildcard/broad bind | **FIXED** — scoped bind + SG rules |
| 7 | MEDIUM | Manager | Cassandra crash-loop impacting TheHive stability | **FIXED** — service recovery |
| 8 | MEDIUM | Manager | Wazuh Dashboard/API/enrollment ports over-open | **FIXED** — admin IP + VPC-only |
| 9 | MEDIUM | All | Stale Security Group rules | **FIXED** — cleaned on re-check |
| 10 | LOW/MED | All | Package/local hygiene items | **FIXED** |
| 11–13 | LOW/INFO | All | Residual hardening notes | **FIXED** / confirmed good |

### Accepted Risk — Passwordless Sudo

Default `ubuntu` user can sudo without a password (AWS EC2 cloud-init norm across all 3 nodes). Changing this mid-lab risked locking out the only admin path, so it's a **formal, documented risk acceptance** for this educational lab — not an oversight. Production/clinical deployments would require least-privilege sudo, break-glass accounts, and MFA on admin paths.

This transparency is intentional: it shows **decision-making under constraint**, not just a checklist of green ticks.

### Post-Audit Network Posture

- Same VPC, private IPs only for node-to-node EDR traffic
- SSH and SOC management ports scoped to operator admin IP + VPC CIDR
- Report sync remains key-based SCP/SSH
- Public GitHub tree contains **no** TLS private keys or Velociraptor private keys

---
Yeh do sections alag se — seedha copy karo:



**2. Repository Layout**

## 📁 Repository Layout

Healthcare_IOMT-EDR/

├── README.md

├── .gitignore

├── security-audit-scans/ # Per-node self-audit scripts

│ ├── security_audit_scan_agent.sh
│ ├── security_audit_scan_manager.sh
│ └── security_audit_scan_forensics.sh

├── manager/

│ ├── healthcare-edr/ # Core SOC stack

│ │ ├── live_edr_iomt.py
│ │ ├── live_complainace_iomt.py # HIPAA + HITRUST + NIST (live)
│ │ ├── run_compliance_and_sync.sh
│ │ ├── auto_contain.py
│ │ ├── thehive_integration_iomt.py
│ │ ├── ml_enrichment_iomt.py / iomt_guard_ml.py / train_*.py
│ │ ├── detection-rules/ # sigma / kql / spl / wazuh-native
│ │ ├── config/ # Wazuh, compliance_report.py, YARA rules
│ │ ├── models/ # Trained Isolation Forest + Random Forest

│ │ └── ...
│ ├── pretty_all_reports.py
│ ├── pretty_compliance.py
│ └── soc_analyst_fixes/

├── agent/

│ ├── one_click_demo.sh
│ ├── run_demo_attacks_iomt.sh
│ ├── capture_and_transfer.sh
│ ├── simulate_medical_device.py
│ └── atomic_validation_v2.sh

└── forensics/

├── forensics-tools/

│ ├── generate_report.py # TShark + Volatility3
│ └── build_index.sh
├── pcap_phi_credential_check.py
└── pretty_forensic.py / pretty_phi.py


Not in repo (by design):** TLS private keys, Velociraptor client/API private keys, live `.jsonl` logs, raw pcaps, `.lime` memory dumps, generated HTML/JSON compliance dumps, backup tarballs. See `.gitignore`.

---

## ▶️ Demo Run (Verified Sequence)

**Terminal 1 — Manager**
```bash
cd ~/healthcare-edr
python3 live_edr_iomt.py          # leave running
```

**Terminal 2 — Agent**
```bash
cd ~
./one_click_demo.sh               # ~4 min; wait for completion
```

**Back on Manager**
```bash
# Ctrl+C live_edr when demo done
cd ~/healthcare-edr
./run_compliance_and_sync.sh      # NIST/PCI/ISO + HIPAA/HITRUST + sync to Forensics
python3 ~/pretty_all_reports.py
```

**Terminal 3 — Forensics**
```bash
cd ~/forensics-tools
PCAP=$(ls -t ~/pcap_captures/*.pcap | head -1)
python3 generate_report.py "$PCAP"   # do not Ctrl+C — memory scan can take minutes
python3 ~/pretty_forensic.py
python3 ~/pcap_phi_credential_check.py "$PCAP"
python3 ~/pretty_phi.py
./build_index.sh
```

---

## ⚠️ Known Limitations (Documented, Not Hidden)

1. **Cortex analyzers** — not fully integrated (arm64/amd64 Docker incompatibility on lab instances); jobs trigger but per-analyzer result depth is limited
2. **MITRE keyword gaps** — a subset of alert descriptions in the live compliance mapper still map to `T0000/Unknown`
3. **ML evaluation scale** — models trained/evaluated on lab/simulated traffic; treat metrics as lab results, not multi-site production validation
4. **Lab-only accepted risk** — passwordless sudo for the default `ubuntu` cloud user (see audit above)

---

## 📜 License / Use

Educational / portfolio / diploma capstone lab. Not a certified medical device or production hospital SOC product. Do not deploy against real patient-care networks without formal clinical engineering, privacy, and change-control processes.

---

## 👤 Author

**Dr. Kainat Zahra Khalil**
BDS · PMDC-registered Dental Surgeon · EduQual Level 6 Diploma in AI Operations
Transitioning clinical healthcare expertise into hands-on blue-team engineering — SOC Analyst / EDR Analyst / Healthcare Security Analyst track, with a long-term goal of building a healthcare cybersecurity SaaS company.

GitHub: [@k-z33](https://github.com/k-z33)
