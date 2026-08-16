"""
IoMT ML Enrichment Layer (SAFE, ADDITIVE INTEGRATION)
======================================================
Ye purane, already-tested analyze_iomt() (rule-based, MITRE+HIPAA+patient-safety
escalation) ko REPLACE nahi karta — ye ek OPTIONAL enrichment layer hai jo
analyze_iomt() ke result dict mein ML fields ADD karta hai, agar models
available hon.
"""

import os

try:
    import numpy as np
    import joblib
    ML_LIBS_AVAILABLE = True
except ImportError:
    ML_LIBS_AVAILABLE = False

try:
    from feature_extractor_iomt import extract_features
    FEATURE_EXTRACTOR_AVAILABLE = True
except ImportError:
    FEATURE_EXTRACTOR_AVAILABLE = False

MODELS_DIR_CANDIDATES = [
    os.path.expanduser("~/healthcare-edr/models"),
    "models",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "models"),
]

_iso_model = None
_rf_model = None
ML_MODELS_LOADED = False

if ML_LIBS_AVAILABLE and FEATURE_EXTRACTOR_AVAILABLE:
    for _model_dir in MODELS_DIR_CANDIDATES:
        _iso_path = os.path.join(_model_dir, "isolation_forest_iomt.pkl")
        _rf_path = os.path.join(_model_dir, "random_forest_iomt.pkl")
        if os.path.exists(_iso_path) and os.path.exists(_rf_path):
            try:
                _iso_model = joblib.load(_iso_path)
                _rf_model = joblib.load(_rf_path)
                ML_MODELS_LOADED = True
                print(f"IoMT ML enrichment models loaded from: {_model_dir}")
                break
            except Exception as e:
                print(f"IoMT ML enrichment model load error: {e}")

if not ML_MODELS_LOADED:
    print("IoMT ML enrichment: models not found — running rule-based only (no ML overlay)")

_IOMT_ML_LABELS = {
    0: "BENIGN",
    1: "UNAUTHORIZED_ACCESS",
    2: "FIRMWARE_TAMPERING",
    3: "DATA_EXFILTRATION",
    4: "NETWORK_ANOMALY",
}


def enrich_with_ml(alert: dict, base_result: dict) -> dict:
    """
    base_result = output of the existing, tested analyze_iomt().
    Returns the SAME dict with extra keys added (never removes/overwrites
    existing keys like 'action', 'severity', 'mitre', 'hipaa_citation').
    """
    if not ML_MODELS_LOADED:
        base_result["ml_available"] = False
        return base_result

    try:
        features = extract_features(alert)
        f = np.array(features, dtype=float).reshape(1, -1)

        f_scaled = _iso_model.named_steps["scaler"].transform(f)
        score = float(_iso_model.named_steps["model"].decision_function(f_scaled)[0])
        is_anom = bool(_iso_model.predict(f_scaled)[0] == -1)

        rf_class = int(_rf_model.predict(f)[0])
        rf_proba = _rf_model.predict_proba(f)[0]
        threat_type = _IOMT_ML_LABELS.get(rf_class, "UNKNOWN")
        confidence = float(max(rf_proba))

        base_result["ml_available"] = True
        base_result["ml_score"] = round(score, 4)
        base_result["ml_is_anomaly"] = is_anom
        base_result["ml_threat_type"] = threat_type
        base_result["ml_confidence"] = round(confidence, 3)
    except Exception as e:
        base_result["ml_available"] = False
        base_result["ml_error"] = str(e)

    return base_result
