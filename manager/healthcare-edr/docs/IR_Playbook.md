# Incident Response Playbook — IoMT Device Compromise
### Scenario: Device Impersonation / MAC-IP Mismatch (Wazuh Rule 100210)

Structured on **NIST SP 800-61 Rev. 2** (Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident Activity).

---

## 1. Preparation

**Assets in scope:** Infusion pumps, ventilators, patient monitors, imaging devices, pharmacy dispensing cabinets on the clinical VLAN.

**Tools ready before an incident:**
- Wazuh Manager (detection) — rules 100200–100241 active
- TheHive (case management) — auto-case-creation confirmed working
- Velociraptor (forensic collection) — tied to TheHive case
- `chain_of_custody.py` — evidence hash-tracking
- Device inventory (`device_inventory.json`) — vendor, model, firmware, last patch date per device

**Roles (map to your actual org when deployed in production):**
| Role | Responsibility |
|---|---|
| SOC Analyst (Tier 1) | First triage, confirms alert is not a false positive |
| Incident Handler (Tier 2) | Runs containment, coordinates with biomedical engineering |
| Biomedical Engineering | Physical device access, safe device isolation without disrupting patient care |
| Compliance Officer | HIPAA breach-notification assessment, regulatory timeline |
| Clinical Lead / Charge Nurse | Patient-safety decision authority if a device must be taken offline mid-use |

---

## 2. Detection & Analysis

**Trigger:** Wazuh rule `100210` fires — `CRITICAL: Possible device impersonation for $(device_id), MAC and IP mismatch detected` (level 13, MITRE T1557 — Adversary-in-the-Middle).

**Triage checklist (Tier 1, target: within 5 minutes of alert):**
- [ ] Confirm the alert against the device inventory — is `$(device_id)` a known/registered device?
- [ ] Check `ml_enrichment` confidence score in the same log entry (Isolation Forest / Random Forest) — is this consistent with historical false positives for this device?
- [ ] Run `threat_intel_enrichment.py` against any external IP involved — malicious reputation raises confidence this is real
- [ ] Escalate to Tier 2 if: device is patient-safety-critical (infusion pump/ventilator/patient monitor) **OR** ML confidence is high **OR** threat-intel verdict is malicious

**Analysis (Tier 2):**
- [ ] Pull the TheHive case (auto-created) — confirm Velociraptor collection has started
- [ ] Verify evidence integrity: `python3 chain_of_custody.py verify --case-id <ID> --file <evidence_path>`
- [ ] Log `metrics.py` stage: `python3 metrics.py log --case-id <ID> --stage case_created`

---

## 3. Containment, Eradication & Recovery

**Containment decision tree:**

```
Is the device patient-safety-critical (infusion pump / ventilator / patient monitor)?
  │
  ├── YES → Do NOT auto-isolate without clinical sign-off.
  │         Notify Clinical Lead immediately. Isolate only after
  │         clinical confirmation that patient is not actively dependent
  │         on the device, OR a backup device is in place.
  │
  └── NO  → auto_contain.py may isolate automatically per existing logic
```

- [ ] If auto-contain fires: confirm isolation action logged (`metrics.py log --stage containment_action`)
- [ ] If manual containment required: Biomedical Engineering physically disconnects/quarantines device from clinical VLAN
- [ ] Preserve evidence before any device reset — Velociraptor collection must complete BEFORE containment wipes volatile data
- [ ] Eradication: reset device to known-good firmware (verify signature per `update-mechanism checklist`), rotate any credentials involved
- [ ] Recovery: device re-added to network only after MAC/IP re-validated against inventory

**Communication timeline:**
| Time from detection | Action |
|---|---|
| 0–5 min | Tier 1 triage, escalate if criteria met |
| 5–15 min | Tier 2 analysis, Clinical Lead notified if patient-safety device |
| 15–30 min | Containment decision executed |
| Within 1 hour | Compliance Officer briefed if PHI exposure suspected |
| Within 24 hours (if confirmed breach) | HIPAA breach-notification clock starts — Compliance Officer owns this |

---

## 4. Post-Incident Activity

- [ ] Full investigation report generated (`generate_forensic_report.py --case-id <ID>`) including chain-of-custody section
- [ ] `metrics.py report` — record final MTTD/MTTC/MTTR for this case in the post-incident review
- [ ] Root-cause documented in TheHive case notes
- [ ] Device inventory updated if firmware/credentials were rotated
- [ ] Lessons-learned review: did detection fire fast enough? Was the Sigma-layer mapping (MITRE T1557) accurate? Any Wazuh rule tuning needed to reduce false positives for this device type?
- [ ] Update this playbook if the response process needs a step correction

---

## Escalation Matrix (severity-based)

| Wazuh Level | Sigma Severity | Response SLA | Escalation |
|---|---|---|---|
| 14–15 | Critical | Immediate (Tier 2 direct) | Clinical Lead + Compliance Officer notified in parallel |
| 12–13 | High | Within 15 min | Tier 1 → Tier 2 |
| 9–11 | Medium | Within 1 hour | Tier 1 handles, escalate if pattern repeats |
| 7–8 | Low | Next business day review | Logged, trended, no immediate action |

---

*This playbook covers the device-impersonation scenario as a template. Duplicate this structure for other high-severity rule categories (firmware tampering — 100206, HL7 tampering — 100222, ARP spoofing — 100234) as time permits.*
