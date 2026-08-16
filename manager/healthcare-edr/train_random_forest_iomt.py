"""
IoMT Random Forest — Supervised Threat Classification
======================================================
Known IoMT threat categories classify karta hai.
Labeled training data se seekhta hai.

Same structure as train_random_forest.py (generic EDR project) —
labels swapped from generic malware families to IoMT-specific categories,
feature vector extended from 8 to 11 (patient-safety + criticality + firmware kw).

Objective: a.ii — Process/behaviour analysis using supervised learning
Algorithm : Supervised → suitable for known threat categories
"""

import os
import json
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report
from datetime import datetime, timezone

MODELS_DIR = os.path.expanduser("~/healthcare-edr/models")
os.makedirs(MODELS_DIR, exist_ok=True)

# ── IoMT Threat Label Map ───────────────────────────────────────────────────────
# Examiner ko yeh explain karo: har class ka feature pattern alag hai,
# aur ye directly tumhare live_compliance_iomt_v2.py ke MITRE mapping se
# corresponds karta hai (UNAUTHORIZED_ACCESS -> T1078, etc.)
LABELS = {
    0: "BENIGN",
    1: "UNAUTHORIZED_ACCESS",    # default creds, legacy protocol, rogue device — T1078
    2: "FIRMWARE_TAMPERING",     # unrecognized/unauthorized firmware update — T1542
    3: "DATA_EXFILTRATION",      # unusual outbound / large data transfer — T1537
    4: "NETWORK_ANOMALY",        # scans, reconnaissance, unusual traffic — T1046
}

MITRE_MAP_IOMT = {
    "UNAUTHORIZED_ACCESS": "T1078",
    "FIRMWARE_TAMPERING": "T1542",
    "DATA_EXFILTRATION": "T1537",
    "NETWORK_ANOMALY": "T1046",
}

SAMPLES_PER_CLASS = 1500  # 5 classes x 1500 = 7500 total


# ── Data Generator ────────────────────────────────────────────────────────────
def generate_data():
    """
    Har IoMT threat class ka characteristic feature pattern generate karo.
    Real environment mein yeh labeled Wazuh alerts se aata hai (ya
    step1_2_feature_engineering.py jaisa auto-labeling script se).

    Feature order (11): rule_level, hour_of_day, is_business_hours,
    has_network_event, has_external_ip, syscheck_changed, auth_event,
    is_high_rule, is_patient_safety_device, device_criticality_score,
    firmware_or_tamper_kw
    """
    np.random.seed(42)
    X_list, y_list = [], []

    for label_id, label_name in LABELS.items():
        for _ in range(SAMPLES_PER_CLASS):

            if label_name == "BENIGN":
                # Normal: low rule, business hours, mostly internal, no firmware kw
                row = [
                    float(np.random.randint(1, 8)),
                    float(np.random.randint(8, 18)),
                    1.0,
                    float(np.random.choice([0, 1], p=[0.70, 0.30])),
                    0.0,
                    float(np.random.choice([0, 1], p=[0.80, 0.20])),
                    float(np.random.choice([0, 1], p=[0.90, 0.10])),
                    0.0,
                    float(np.random.choice([0, 1], p=[0.65, 0.35])),
                    float(np.random.choice([0, 1, 2], p=[0.10, 0.55, 0.35])),
                    0.0,
                ]

            elif label_name == "UNAUTHORIZED_ACCESS":
                # Default creds / legacy protocol / rogue device: high auth_event,
                # medium-high rule, external IP sometimes, any device criticality
                row = [
                    float(np.random.randint(8, 13)),
                    float(np.random.randint(0, 24)),
                    float(np.random.choice([0, 1])),
                    float(np.random.choice([0, 1], p=[0.40, 0.60])),
                    float(np.random.choice([0, 1], p=[0.50, 0.50])),
                    0.0,
                    1.0,
                    float(np.random.choice([0, 1], p=[0.40, 0.60])),
                    float(np.random.choice([0, 1], p=[0.55, 0.45])),
                    float(np.random.choice([0, 1, 2], p=[0.15, 0.50, 0.35])),
                    0.0,
                ]

            elif label_name == "FIRMWARE_TAMPERING":
                # Unrecognized firmware update: high rule, syscheck triggered,
                # firmware keyword present, disproportionately patient-safety devices
                row = [
                    float(np.random.randint(12, 16)),
                    float(np.random.randint(0, 24)),
                    float(np.random.choice([0, 1], p=[0.30, 0.70])),
                    float(np.random.choice([0, 1], p=[0.60, 0.40])),
                    float(np.random.choice([0, 1], p=[0.60, 0.40])),
                    1.0,
                    0.0,
                    1.0,
                    float(np.random.choice([0, 1], p=[0.30, 0.70])),
                    float(np.random.choice([1, 2], p=[0.25, 0.75])),
                    1.0,
                ]

            elif label_name == "DATA_EXFILTRATION":
                # Unusual outbound transfer: network event + external IP,
                # high rule level, off-hours common
                row = [
                    float(np.random.randint(10, 15)),
                    float(np.random.randint(18, 24)),
                    0.0,
                    1.0,
                    1.0,
                    0.0,
                    0.0,
                    1.0,
                    float(np.random.choice([0, 1], p=[0.55, 0.45])),
                    float(np.random.choice([0, 1, 2], p=[0.15, 0.55, 0.30])),
                    0.0,
                ]

            else:  # NETWORK_ANOMALY
                # Scans / reconnaissance / unusual traffic: network event,
                # external IP frequent, medium rule level
                row = [
                    float(np.random.randint(8, 13)),
                    float(np.random.randint(0, 24)),
                    float(np.random.choice([0, 1])),
                    1.0,
                    float(np.random.choice([0, 1], p=[0.35, 0.65])),
                    0.0,
                    0.0,
                    float(np.random.choice([0, 1], p=[0.50, 0.50])),
                    float(np.random.choice([0, 1], p=[0.60, 0.40])),
                    float(np.random.choice([0, 1, 2], p=[0.15, 0.55, 0.30])),
                    0.0,
                ]

            X_list.append(row)
            y_list.append(label_id)

    return np.array(X_list), np.array(y_list)


# ── Train ──────────────────────────────────────────────────────────────────────
def train():
    print("=" * 55)
    print(" IoMT Random Forest — Supervised Threat Classifier")
    print("=" * 55)

    print(f"\n[1/4] Generating labelled dataset "
          f"({len(LABELS)} classes x {SAMPLES_PER_CLASS} samples)...")
    X, y = generate_data()
    print(f"  Total samples : {len(X):,}")

    print("\n[2/4] Train / test split (80/20, stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print("[3/4] Building pipeline...")
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=300,
            max_depth=15,
            min_samples_split=5,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )),
    ])
    pipeline.fit(X_train, y_train)

    # ── Evaluation ────────────────────────────────────────────────────────────
    print("\n[4/4] Evaluation...")
    y_pred = pipeline.predict(X_test)
    print(classification_report(
        y_test, y_pred,
        target_names=list(LABELS.values()),
        digits=3,
    ))

    cv_scores = cross_val_score(pipeline, X, y, cv=5, scoring="f1_weighted")
    print(f"  Cross-val F1 (5-fold): {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")

    # ── Feature importance ────────────────────────────────────────────────────
    feat_names = [
        "rule_level", "hour_of_day", "business_hours", "network_event",
        "external_ip", "file_change", "auth_event", "high_rule",
        "patient_safety_device", "device_criticality", "firmware_tamper_kw",
    ]
    importances = sorted(
        zip(feat_names, pipeline.named_steps["clf"].feature_importances_),
        key=lambda x: x[1], reverse=True,
    )
    print("\n Top Feature Importances:")
    for fname, imp in importances[:6]:
        bar = "█" * int(imp * 50)
        print(f"   {fname:<22} {bar} {imp:.3f}")

    # ── Save ──────────────────────────────────────────────────────────────────
    model_path = os.path.join(MODELS_DIR, "random_forest_iomt.pkl")
    joblib.dump(pipeline, model_path)
    joblib.dump(feat_names, os.path.join(MODELS_DIR, "feature_names_iomt.pkl"))

    stats = {
        "model": "RandomForestClassifier",
        "type": "Supervised",
        "variant": "IoMT (5 classes, 11 features)",
        "n_estimators": 300,
        "classes": LABELS,
        "mitre_map": MITRE_MAP_IOMT,
        "f1_cv_mean": round(float(cv_scores.mean()), 3),
        "f1_cv_std": round(float(cv_scores.std()), 3),
        "training_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "use_case": "Known IoMT threat category classification",
    }
    stats_path = os.path.join(MODELS_DIR, "random_forest_iomt_stats.json")
    with open(stats_path, "w") as f:
        json.dump(stats, f, indent=2)

    print(f"\n✅ Saved → {model_path}")
    print(f"✅ Saved → {stats_path}")


if __name__ == "__main__":
    train()
