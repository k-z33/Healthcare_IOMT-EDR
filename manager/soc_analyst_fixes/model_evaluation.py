#!/usr/bin/env python3
import json, argparse
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

def load_from_json(path):
    y_true, y_pred = [], []
    with open(path) as f:
        for line in f:
            if line.strip():
                entry = json.loads(line)
                y_true.append(int(entry["true_label"]))
                y_pred.append(int(entry["predicted_label"]))
    return y_true, y_pred

def evaluate(y_true, y_pred):
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)
    return precision, recall, f1, cm

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", required=True)
    args = ap.parse_args()
    y_true, y_pred = load_from_json(args.json)
    p, r, f, cm = evaluate(y_true, y_pred)
    print(f"\n=== ML Model Evaluation ===")
    print(f"Precision: {p*100:.2f}%")
    print(f"Recall: {r*100:.2f}%")
    print(f"F1 Score: {f*100:.2f}%")
    print(f"Confusion Matrix:\n{cm}")
