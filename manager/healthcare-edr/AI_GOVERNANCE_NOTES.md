# AI Governance Notes — ML Overlay (Healthcare IoMT EDR)

**Scope:** `ml_enrichment_iomt.py` (Isolation Forest + Random Forest, 11
features) as used in this project. This is a lightweight governance
mapping, not a full NIST AI RMF program — appropriate for the scale of
a single-analyst lab project, written to show the *reasoning*, not to
claim enterprise-grade AI governance.

## Core principle

**The ML overlay is advisory, not authoritative.** It adds a
score/anomaly flag/predicted category alongside each Wazuh alert. It
never auto-closes, auto-escalates, or auto-contains a device by itself
— `auto_contain.py`'s rule-based, patient-safety-aware logic remains
the decision-maker. This distinction is the single most important
governance control in the system.

## Mapping to NIST AI RMF functions

| NIST AI RMF Function | What it asks | How this project addresses it |
|---|---|---|
| **Govern** | Who is accountable for AI-driven decisions? | Documented here: ML output is advisory only; the human analyst (or the deterministic rule engine) makes the final call. No autonomous action is taken on ML output alone. |
| **Map** | What is the AI used for, and what could go wrong? | Used for: anomaly scoring / predicted attack category on top of rule-based Wazuh alerts. Failure mode: a confident-but-wrong prediction could mislead an analyst — mitigated by the confidence threshold below. |
| **Measure** | How is performance and risk tracked? | Every prediction is logged (`ml_audit_logger.py`) with a confidence score. Predictions below 0.65 confidence are automatically flagged `needs_human_review = True` in the audit log. |
| **Manage** | How are risks responded to over time? | Low-confidence and human-overridden predictions are queryable from the JSON audit log (`~/healthcare-edr/logs/edr_events.jsonl`, `event_type: ml_prediction`) — enabling periodic review of where the model is uncertain or wrong, to inform retraining. |

## What this is *not*

- Not a claim of formal NIST AI RMF certification or a completed AI risk
  assessment.
- Not covering MITRE ATLAS or OWASP LLM Top 10 — this project doesn't
  use an LLM/agentic component, so those frameworks don't apply here.
  (Noted for future reference if an LLM-based triage assistant is ever
  added to this pipeline.)

## Why this matters for a healthcare context specifically

An ML model silently mis-scoring a ventilator or infusion-pump alert
carries direct patient-safety risk, not just a security-metrics risk.
The confidence-threshold + audit-log design here exists specifically so
a low-confidence ML call on a patient-safety device is never the last
word — it surfaces for human review instead of being trusted blindly.
