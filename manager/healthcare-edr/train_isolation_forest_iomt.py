"""
IoMT Isolation Forest — Unsupervised Anomaly Detection
=======================================================
Unknown IoMT threats detect karta hai — koi labeled data zaroori nahi.
30-day endpoint baseline se seekhta hai aur deviations flag karta hai.

Same structure as train_isolation_forest.py (generic EDR project) —
extended from 8 to 11 features to capture IoMT patient-safety risk.

Objective: a.i — ML models for baseline establishment & anomaly detection
Algorithm : Unsupervised → suitable for zero-day / unknown threats
"""

import os
import json
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from datetime import datetime, timezone

MODELS_DIR = os.path.expanduser("~/healthcare-edr/models")
os.makedirs(MODELS_DIR, exist_ok=True)


# ── Synthetic Baseline Data Generator ─────────────────────────────────────────
def generate_training_data():
    """
    Real environment mein yeh data Elasticsearch/Wazuh se aata hai
    (last 30 days ke IoMT alerts). Demo/exam ke liye synthetic data
    generate karte hain — same approach jo generic EDR project mein use hui.

    Feature order (11): rule_level, hour_of_day, is_business_hours,
    has_network_event, has_external_ip, syscheck_changed, auth_event,
    is_high_rule, is_patient_safety_device, device_criticality_score,
    firmware_or_tamper_kw

    Returns
    -------
    X_train : ndarray shape (N, 11)
    """
    np.random.seed(42)

    # ── Normal behaviour (10,000 samples — 30-day baseline) ───────────────────
    # low rule_level, business hours, mostly internal, mixed device criticality,
    # no firmware/tamper keywords
    N_NORMAL = 10_000
    X_normal = np.column_stack([
        np.random.randint(1, 8, N_NORMAL).astype(float),                       # rule_level
        np.random.randint(8, 18, N_NORMAL).astype(float),                      # hour_of_day
        np.ones(N_NORMAL),                                                     # is_business_hours
        np.random.choice([0, 1], N_NORMAL, p=[0.70, 0.30]),                    # has_network
        np.zeros(N_NORMAL),                                                    # has_external_ip
        np.random.choice([0, 1], N_NORMAL, p=[0.80, 0.20]),                    # syscheck_changed
        np.random.choice([0, 1], N_NORMAL, p=[0.90, 0.10]),                    # auth_event
        np.zeros(N_NORMAL),                                                    # is_high_rule
        np.random.choice([0, 1], N_NORMAL, p=[0.65, 0.35]),                    # is_patient_safety_device
        np.random.choice([0, 1, 2], N_NORMAL, p=[0.10, 0.55, 0.35]),           # device_criticality_score
        np.zeros(N_NORMAL),                                                    # firmware_or_tamper_kw
    ])

    # ── Attack patterns (500 samples — 5% contamination) ──────────────────────
    # High rule_level, off-hours, external C2, mass file/firmware changes,
    # disproportionately hitting patient-safety devices (that's the IoMT risk)
    N_ATTACK = 500
    X_attack = np.column_stack([
        np.random.randint(12, 16, N_ATTACK).astype(float),
        np.random.randint(0, 6, N_ATTACK).astype(float),
        np.zeros(N_ATTACK),
        np.ones(N_ATTACK),
        np.ones(N_ATTACK),
        np.ones(N_ATTACK),
        np.zeros(N_ATTACK),
        np.ones(N_ATTACK),
        np.random.choice([0, 1], N_ATTACK, p=[0.35, 0.65]),                    # more patient-safety hits
        np.random.choice([1, 2], N_ATTACK, p=[0.30, 0.70]),
        np.random.choice([0, 1], N_ATTACK, p=[0.40, 0.60]),
    ])

    X_train = np.vstack([X_normal, X_attack])

    print(f"  Total training samples : {len(X_train):,}")
    print(f"  Normal                 : {len(X_normal):,}")
    print(f"  Attack (contamination) : {len(X_attack):,}")

    return X_train, X_normal, X_attack


# ── Train ──────────────────────────────────────────────────────────────────────
def train():
    print("=" * 55)
    print(" IoMT Isolation Forest — Unsupervised Anomaly Detection")
    print("=" * 55)

    print("\n[1/4] Generating 30-day IoMT baseline data...")
    X_train, X_normal, X_attack = generate_training_data()

    print("\n[2/4] Building pipeline (StandardScaler + IsolationForest)...")
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("model", IsolationForest(
            n_estimators=200,       # 200 trees
            contamination=0.05,     # 5% expected anomalies in training set
            random_state=42,
            n_jobs=-1,
        )),
    ])

    print("[3/4] Fitting model...")
    pipeline.fit(X_train)

    print("\n[4/4] Evaluating model...")
    normal_scores = pipeline.named_steps["model"].decision_function(
        pipeline.named_steps["scaler"].transform(X_normal[:500])
    )
    attack_scores = pipeline.named_steps["model"].decision_function(
        pipeline.named_steps["scaler"].transform(X_attack)
    )
    normal_preds = pipeline.predict(pipeline.named_steps["scaler"].transform(X_normal[:500]))
    attack_preds = pipeline.predict(pipeline.named_steps["scaler"].transform(X_attack))

    # 1 = normal, -1 = anomaly
    normal_acc = (normal_preds == 1).sum() / len(normal_preds) * 100
    attack_acc = (attack_preds == -1).sum() / len(attack_preds) * 100

    print(f"  Normal avg score : {np.mean(normal_scores):+.3f} (positive = normal)")
    print(f"  Attack avg score : {np.mean(attack_scores):+.3f} (negative = anomaly)")
    print(f"  Normal accuracy  : {normal_acc:.1f}% (correctly classified as normal)")
    print(f"  Attack accuracy  : {attack_acc:.1f}% (correctly classified as anomaly)")

    # ── Save ──────────────────────────────────────────────────────────────────
    model_path = os.path.join(MODELS_DIR, "isolation_forest_iomt.pkl")
    joblib.dump(pipeline, model_path)

    stats = {
        "model": "IsolationForest",
        "type": "Unsupervised",
        "variant": "IoMT (11 features)",
        "n_estimators": 200,
        "contamination": 0.05,
        "training_samples": int(len(X_train)),
        "normal_accuracy": round(normal_acc, 2),
        "attack_accuracy": round(attack_acc, 2),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "threshold_note": "score < -0.1 = anomaly, < -0.3 = critical",
        "use_case": "Unknown IoMT threat detection — no labels needed",
    }
    stats_path = os.path.join(MODELS_DIR, "isolation_forest_iomt_stats.json")
    with open(stats_path, "w") as f:
        json.dump(stats, f, indent=2)

    print(f"\n✅ Saved → {model_path}")
    print(f"✅ Saved → {stats_path}")
    print("\n Model Stats:")
    for k, v in stats.items():
        print(f"   {k:<22}: {v}")


if __name__ == "__main__":
    train()
