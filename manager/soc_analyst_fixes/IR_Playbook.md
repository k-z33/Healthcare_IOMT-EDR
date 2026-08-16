# Incident Response Playbook — IoMT Device Compromise

## 1. Preparation

**Tools ready:** Wazuh, TheHive, Velociraptor, chain_of_custody.py, metrics.py

## 2. Detection & Analysis

**Trigger:** Wazuh rule 100210 — Device impersonation

**Triage checklist:**
- [ ] Confirm device in inventory
- [ ] Check ML confidence score (>0.75 = high confidence)
- [ ] Run threat_intel_enrichment.py on external IPs
- [ ] Escalate if patient-safety-critical device

## 3. Containment

**Decision tree:**
- Patient-safety-critical (infusion pump/ventilator) → Escalate to Clinical Lead first
- Non-critical → Auto-contain allowed

## 4. Post-Incident

- [ ] Generate forensic report
- [ ] Run metrics.py report
- [ ] Document lessons learned
