
Healthcare IoMT AI-Driven EDR Platform

**Author:** Dr. Kainat Zahra Khalil, BDS · EduQual Level 6 Diploma in AI Operations  
**Repo:** [github.com/k-z33/Healthcare_IOMT-EDR](https://github.com/k-z33/Healthcare_IOMT-EDR)  
**Status:** Complete (with documented known limitations) · August 2026

AI-driven **Endpoint Detection and Response (EDR)** purpose-built for **hospital IoMT** environments — infusion pumps, ventilators, patient monitors, imaging devices (DICOM), pharmacy cabinets, and related clinical endpoints.

Combines native SIEM (Wazuh), ML anomaly scoring, **patient-safety-aware** containment, SOC case management (TheHive), digital forensics (Velociraptor + TShark + Volatility3), detection-as-code (Sigma → Wazuh / KQL / SPL), and compliance reporting mapped to **HIPAA**, **HITRUST**, **NIST CSF**, **PCI-DSS**, **ISO 27001**, and **MITRE ATT&CK / ATT&CK for ICS**.

---

## Architecture — 3-Node AWS Lab

| Role | Private IP | Purpose | Key Software |
|------|------------|---------|--------------|
| **Agent** | `172.31.27.110` | Simulated IoMT / clinical endpoint | Wazuh agent, Suricata, Velociraptor client, attack + capture scripts |
| **Manager** | `172.31.44.154` | SOC server / orchestrator | Wazuh manager, `live_edr_iomt.py`, ML models, TheHive, Cortex, compliance, investigation reports |
| **Forensics** | `172.31.33.186` | DFIR node | Velociraptor server, TShark, Volatility3, pcap PHI/credential scan, HTML report index |

All nodes sit in the same AWS VPC (private networking). Agent → Manager via Wazuh protocol; Manager ↔ Forensics via SSH/SCP (key-based) for report sync. Security Groups hardened post-audit (admin IP + VPC-internal only on management ports).
Agent (attacks + Wazuh events + pcap)
│
▼
Manager: live_edr_iomt.py
→ severity / MITRE / HIPAA mapping
→ ML overlay (Isolation Forest + Random Forest, advisory)
→ patient-safety containment decision
→ TheHive case + investigation report
→ compliance (HIPAA/HITRUST + NIST/PCI/ISO) + sync
│
▼
Forensics: TShark + Volatility3 HTML report

cleartext PHI / credential scan
combined index.html + pretty terminal dashboards

text---

## Healthcare / IoMT Focus

This is not a generic EDR demo. Design choices are driven by **clinical risk**:

| Concern | How the platform addresses it |
|---------|-------------------------------|
| **Patient safety** | Containment logic prefers escalate / monitor over blind isolate when device class is life-supporting (e.g. ventilator, infusion pump) |
| **PHI exposure** | Dedicated pcap cleartext scan for MRN / SSN / DOB patterns and HTTP Basic Auth / password fields |
| **Clinical protocols** | Detection coverage for DICOM exfiltration, HL7 message tampering, pharmacy dispensing anomaly, infusion-pump config change, ventilator anomalous activity |
| **Vendor / BAA risk** | Device inventory + patch-age / unregistered-device flags under HIPAA §164.308(b) Business Associate style section |
| **Compliance** | Live HIPAA Security Rule + HITRUST CSF mapping from real Wazuh alerts; plus industry frameworks (NIST CSF, PCI-DSS, ISO 27001) |

Simulated device classes in demos include: infusion pumps, ventilators, dental/imaging X-ray, pharmacy cabinets, patient monitors.

---

## Detection-as-Code (Sigma + KQL + SPL + Wazuh)

**Location:** `manager/healthcare-edr/detection-rules/`

| Format | Path | Count (approx.) |
|--------|------|-----------------|
| **Sigma YAML** | `detection-rules/sigma/*.yml` | ~32 IoMT-focused rules |
| **KQL** | `detection-rules/kql/*.kql` | Matching conversions |
| **SPL** | `detection-rules/spl/*.spl` | Matching conversions |
| **Wazuh native XML** | `detection-rules/wazuh-native/` + `rules/` | Custom IoMT + network security rules |
| **ATT&CK Navigator** | `sigma/navigator_layer*.json` | Enterprise + ICS layers |

### Example Sigma rule themes (healthcare-specific)

- `dicom_exfiltration.yml` — imaging data leaving expected paths  
- `hl7_message_tampering.yml` — clinical message integrity  
- `infusion_pump_config_change.yml` — therapy parameter changes  
- `ventilator_anomalous_activity.yml` — respiratory device anomalies  
- `pharmacy_dispensing_anomaly.yml` — dispensing pattern deviation  
- `patient_monitor_anomaly.yml` — telemetry / monitoring abuse  
- `unencrypted_phi_transmission.yml` — cleartext clinical data  
- `legacy_insecure_protocol.yml` — insecure management protocols on clinical devices  
- `device_impersonation.yml` / `rogue_device_detected.yml` — identity spoofing on the ward network  
- `network_segmentation_violation.yml` / `lateral_movement_segment.yml` — flat-network / cross-segment movement  
- `arp_spoofing_mitm.yml` / `rogue_dhcp_server.yml` — local network attacks against medical VLANs  
- Plus: port scan, default credentials, firmware update, reboot, time-sync anomaly, TLS validation failure, etc.

Rules are MITRE-tagged where mapped; a known gap is partial keyword coverage in one compliance mapper (some alerts fall back to `T0000/Unknown`) — documented honestly for follow-up.

---

## Project Layers

| # | Layer | What it does |
|---|--------|--------------|
| 1 | **Detection** | Wazuh custom rules + Sigma detection-as-code |
| 2 | **Structured logging** | JSON decision log (alert → ML → contain → case) |
| 3 | **ML overlay** | Isolation Forest + Random Forest (advisory scoring) |
| 4 | **Response & orchestration** | Patient-safety containment + TheHive + Velociraptor trigger |
| 5 | **Visualization** | OpenSearch / dashboards + colorful terminal pretty-printers |
| 6 | **Vendor / third-party risk** | Device inventory + BAA / patch tracking signals |
| 7 | **Compliance** | HIPAA + HITRUST (live) and NIST CSF + PCI-DSS + ISO 27001 |
| 8 | **AI governance** | ML prediction audit trail + human-review oriented logging |

---

## Repository Layout
Healthcare_IOMT-EDR/
├── README.md
├── .gitignore
├── manager/
│   ├── healthcare-edr/          # Core SOC stack
│   │   ├── live_edr_iomt.py
│   │   ├── live_complainace_iomt.py   # HIPAA + HITRUST + NIST (live)
│   │   ├── run_compliance_and_sync.sh
│   │   ├── auto_contain.py
│   │   ├── thehive_integration_iomt.py
│   │   ├── ml_enrichment_iomt.py / iomt_guard_ml.py / train_*.py
│   │   ├── detection-rules/     # sigma / kql / spl / wazuh-native
│   │   ├── config/              # Wazuh, compliance_report.py, YARA, etc.
│   │   ├── models/              # Trained IF + RF pickles
│   │   └── ...
│   ├── pretty_all_reports.py
│   ├── pretty_compliance.py
│   └── soc_analyst_fixes/
├── agent/
│   ├── one_click_demo.sh
│   ├── run_demo_attacks_iomt.sh
│   ├── capture_and_transfer.sh
│   ├── simulate_medical_device.py
│   ├── atomic_validation_v2.sh
│   └── security_audit_scan.sh
└── forensics/
├── forensics-tools/
│   ├── generate_report.py   # TShark + Volatility3
│   ├── build_index.sh
│   └── ...
├── pcap_phi_credential_check.py
├── pretty_forensic.py / pretty_phi.py
└── security_audit_scan.sh
text**Not in repo (by design):** TLS private keys, Velociraptor client/API private keys, live `.jsonl` logs, raw pcaps, `.lime` memory dumps, generated HTML/JSON compliance dumps, backup tarballs. See `.gitignore`.

---

## Security Audit & Hardening (Self-Performed)

A full security assessment was run across **all three endpoints** (13–14 August 2026), followed by remediation and a second-pass Security Group review.

| Severity | Found | Fixed | Accepted risk |
|----------|-------|-------|---------------|
| Critical | 5 | 4 | 1 (passwordless sudo — AWS cloud-init default; documented) |
| High | 3 | 3 | 0 |
| Medium / Low | 5 | 5 | 0 |
| **Total** | **13** | **12** | **1** |


A structured security assessment was performed against **all three AWS nodes** (Manager, Agent, Forensics) on **13–14 August 2026**, followed by remediation and a second-pass Security Group review. This was not a paper exercise: findings were validated with live commands on each host, fixed where appropriate, and re-checked.

**Outcome: 13 findings tracked · 12 fully remediated · 1 formally accepted lab risk.**

### Scope

| Area | What was reviewed |
|------|-------------------|
| **Host posture** | Users, sudo, SSH, package hygiene, world-writable paths, sensitive file permissions |
| **Application / stack** | Wazuh, TheHive, Cortex, Elasticsearch/OpenSearch, Velociraptor, custom Python EDR code |
| **Secrets in code** | Hardcoded API keys, passwords, `verify=False`, embedded tokens |
| **Network exposure** | AWS Security Groups, bind addresses (0.0.0.0 vs localhost/VPC), management ports |
| **TLS / crypto** | Certificate verification in clients, indexer SSL material handling |
| **Lab ops risk** | Crash-loops (e.g. Cassandra), stale SG rules, leftover admin IPs |

Each endpoint has a **`security_audit_scan.sh`** helper script (see `agent/security_audit_scan.sh` and `forensics/security_audit_scan.sh`) used during the audit/hardening loop to re-run local checks after fixes.

### Findings Summary

| # | Severity | Machine | Finding | Status |
|---|----------|---------|---------|--------|
| 1 | **CRITICAL** | Manager | Hardcoded credentials / secrets in source | **FIXED** — moved to environment variables; no live keys in repo |
| 2 | **CRITICAL** | All 3 | Passwordless sudo for default `ubuntu` user (AWS cloud-init default) | **ACCEPTED RISK** — documented; retrofit risk of lab lockout |
| 3 | **CRITICAL** | Forensics | Elasticsearch / OpenSearch reachable beyond intended scope | **FIXED** — bind + Security Group restricted |
| 4 | **HIGH** | Manager | TLS `verify=False` in integration code | **FIXED** — proper certificate verification |
| 5 | **HIGH** | Manager | TheHive / Cortex management interfaces overly exposed | **FIXED** — SG + listen scope tightened |
| 6 | **HIGH** | Forensics | Velociraptor wildcard / broad bind | **FIXED** — scoped bind + SG rules |
| 7 | **MEDIUM** | Manager | Cassandra crash-loop impacting TheHive stack stability | **FIXED** — service recovery / config cleanup |
| 8 | **MEDIUM** | Manager | Wazuh Dashboard / API / enrollment ports open more broadly than required (e.g. historical 0.0.0.0/0 patterns) | **FIXED** — admin IP + VPC-only |
| 9 | **MEDIUM** | All | Stale Security Group rules (old admin IPs, unused paths) | **FIXED** — SG cleaned on re-check (14 Aug) |
| 10 | **LOW / MED** | All | Package and local hygiene items from scan scripts | **FIXED** |
| 11–13 | **LOW / INFO** | All | Residual hardening notes (logging paths, non-world-writable layout, indexer auth already enforced) | **FIXED** or confirmed already good |

### What Was Already Strong (pre-audit)

- SSH key-based auth (no password SSH for admin access pattern used in lab)
- No careless world-writable project trees on critical paths
- Wazuh indexer authentication enforced
- Sensible separation of Manager / Agent / Forensics roles

### Remediation Themes

1. **Secrets** — Removed hardcoded credentials from Python sources; integrations read from environment / local non-committed config. GitHub repo excludes `*.pem`, `*.key`, Velociraptor client/API key material, `.env`.
2. **TLS** — Eliminated blind `verify=False`; clients use proper trust configuration for lab certs.
3. **Exposure** — Management ports (Wazuh API/dashboard, TheHive, Cortex, Elasticsearch, Velociraptor) no longer left on unrestricted `0.0.0.0/0` where the audit found that pattern; restricted to operator admin IP and VPC-internal traffic.
4. **Stability** — Cassandra-related crash-loop addressed so case-management path remains usable for demos.
5. **Repeatability** — `security_audit_scan.sh` on endpoints supports re-validation after changes.

### Accepted Risk (F2) — Passwordless Sudo

| Item | Detail |
|------|--------|
| **Finding** | Default `ubuntu` user can sudo without password (AWS EC2 cloud-init norm) |
| **Why not “fixed” in lab** | Changing sudoers mid-lab risks lockout of the only admin path; all three nodes share this AWS default |
| **Treatment** | **Formal risk acceptance** for this educational lab only — recorded in the audit report |
| **Production note** | Real SOC / clinical deployments must enforce least-privilege sudo, break-glass accounts, and MFA on admin paths |

This is intentional transparency: portfolio and interview discussions can show **decision-making**, not only green checkmarks.

### Audit Evidence & Documents

| Artefact | Where |
|----------|--------|
| Endpoint scan helpers | `agent/security_audit_scan.sh`, `forensics/security_audit_scan.sh` (Manager equivalents used during live audit) |
| Written audit report | `docs/security-audit/` (e.g. final Security Audit Report DOCX/PDF — add when uploading) |
| Host notes | Optional `audit_manager.txt` / `audit_agent.txt` / `audit_forensics.txt` under `docs/security-audit/` |

### Post-Audit Network Posture (Lab)

- Same VPC, private IPs only for node-to-node EDR traffic  
- SSH and SOC management ports scoped to **operator admin IP** + **VPC CIDR** where previously over-open  
- Report sync Manager → Forensics remains **key-based SCP/SSH**  
- Public GitHub tree contains **no** TLS private keys or Velociraptor private keys  

### Honest Limits

This audit covers the **lab build** (three EC2 instances + compose stacks + custom scripts). It is not a formal pen-test, not HITRUST validated, and not a hospital change-control package. Residual risk remains as in any teaching SOC: demo attack scripts, shared lab credentials model, and accepted AWS default sudo.

---
### Example findings closed

- Hardcoded credentials removed from source (moved to env)  
- TLS `verify=False` eliminated; proper certificate handling  
- Elasticsearch / TheHive / Cortex exposure tightened (no 0.0.0.0/0 on management ports)  
- Velociraptor bind / Security Group rules scoped to admin IP + VPC  
- Stale SG rules and package hygiene cleaned  

Each machine carries a **`security_audit_scan.sh`** helper used during the audit/hardening loop (commands and checks for local posture). Audit narrative docs (Word/PDF) can live under `docs/` — see below.

This is a **lab** environment: accepted risks and residual limitations are written down rather than hidden.

---

## Demo Run (Verified Sequence)

**Terminal 1 — Manager**
```bash
cd ~/healthcare-edr
python3 live_edr_iomt.py          # leave running
Terminal 2 — Agent
Bashcd ~
./one_click_demo.sh               # ~4 min; wait for completion
Manager again
Bash# Ctrl+C live_edr when demo done
cd ~/healthcare-edr
./run_compliance_and_sync.sh      # NIST/PCI/ISO + HIPAA/HITRUST + SCP to Forensics
python3 ~/pretty_all_reports.py
Terminal 3 — Forensics
Bashcd ~/forensics-tools
PCAP=$(ls -t ~/pcap_captures/*.pcap | head -1)
python3 generate_report.py "$PCAP"   # do not Ctrl+C; memory scan can take minutes
python3 ~/pretty_forensic.py
python3 ~/pcap_phi_credential_check.py "$PCAP"
python3 ~/pretty_phi.py
./build_index.sh

Compliance Outputs


GeneratorFrameworksNaturelive_complainace_iomt.pyHIPAA Security Rule, HITRUST CSF, NIST (healthcare-focused)Live — reads Wazuh alerts, device inventory, EDR metricsconfig/compliance_report.pyNIST CSF, PCI-DSS, ISO 27001Real numeric metrics; evidence narrative text is illustrative/template (honestly labeled)
Both are invoked by run_compliance_and_sync.sh and synced to Forensics. HIPAA/HITRUST HTML uses the same “Topper Notes” visual theme as forensic reports for consistent portfolio screenshots.

Known Limitations (Documented)

Cortex analyzers — not fully integrated (arm64/amd64 Docker incompatibility on lab instances). Jobs may trigger; per-analyzer result depth is limited.
MITRE keyword gaps — in the live healthcare compliance mapper, a subset of alert descriptions still map to T0000/Unknown (~partial dictionary coverage).
ML evaluation scale — models are trained/evaluated on lab/simulated traffic; treat precision/recall figures as lab results, not multi-site production validation.
Lab-only accepted risk — passwordless sudo for the default ubuntu cloud user (AWS default); formal risk acceptance recorded in the audit.


License / Use
Educational / portfolio / diploma capstone lab. Not a certified medical device or production hospital SOC product. Do not deploy against real patient-care networks without formal clinical engineering, privacy, and change-control processes.

Author
Dr. Kainat Zahra Khalil
BDS · EduQual Level 6 Diploma in AI Operations
Clinical background (General Dentist) + hands-on healthcare cybersecurity engineering
GitHub: k-z33
