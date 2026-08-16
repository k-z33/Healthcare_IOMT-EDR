"""
ml_audit_logger.py — AI Governance / audit-trail layer for the ML overlay
(ml_enrichment_iomt.py).

This does NOT change how the Isolation Forest / Random Forest models
score alerts. It wraps their output with an accountability record:
who/what made the prediction, how confident it was, and whether a human
reviewed or overrode it — the evidence a NIST AI RMF-style review would
ask for.

Usage (add to ml_enrichment_iomt.py, wherever a prediction is produced):

    from ml_audit_logger import audit_ml_prediction

    prediction = model.predict(features)          # existing line, unchanged
    confidence = model.predict_proba(features)[0]  # existing line, unchanged

    audit_ml_prediction(                            # ADD this one call
        device_id=device_id,
        prediction=prediction,
        confidence=float(max(confidence)),
        anomaly_score=anomaly_score,
    )
"""
import os
import sys

sys.path.insert(0, os.path.expanduser("~/healthcare-edr"))
from structured_logger import get_logger, log_ml_prediction  # noqa: E402

_logger = get_logger("iomt_edr_ml")

# Confidence below this threshold is auto-flagged as "needs human review"
# rather than silently trusted — this is the core AI-governance control.
LOW_CONFIDENCE_THRESHOLD = 0.65


def audit_ml_prediction(device_id, prediction, confidence, anomaly_score=None,
                         human_reviewed=False, reviewer_override=None):
    """Log a single ML prediction to the structured audit log and return
    a governance flag the caller can act on (e.g., escalate to a human
    analyst instead of auto-closing a low-confidence alert)."""
    needs_review = (not human_reviewed) and (confidence < LOW_CONFIDENCE_THRESHOLD)

    log_ml_prediction(
        _logger,
        device_id=device_id,
        prediction=prediction,
        confidence=confidence,
        anomaly_score=anomaly_score,
        human_reviewed=human_reviewed,
        reviewer_override=reviewer_override,
    )

    return {
        "needs_human_review": needs_review,
        "confidence": confidence,
        "threshold": LOW_CONFIDENCE_THRESHOLD,
    }


if __name__ == "__main__":
    # Self-test
    result_high = audit_ml_prediction("ventilator-02", "anomalous", 0.91, -0.5)
    result_low = audit_ml_prediction("infusion-pump-03", "anomalous", 0.42, -0.1)
    print("High-confidence prediction ->", result_high)
    print("Low-confidence prediction  ->", result_low)
    assert result_high["needs_human_review"] is False
    assert result_low["needs_human_review"] is True
    print("[✓] Self-test passed — low-confidence predictions correctly flagged for review.")
