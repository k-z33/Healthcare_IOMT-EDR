#!/usr/bin/env python3
"""
model_evaluation.py

Evaluates the Isolation Forest / Random Forest models against a
labeled test set and produces precision/recall/F1/confusion-matrix
metrics + an HTML report snippet you can paste into the compliance
or capstone report.

Expected input: a CSV with your existing feature columns PLUS a
'true_label' column (1 = actual attack, 0 = actual normal), and a
'predicted_label' column (1 = model flagged as anomaly, 0 = model
said normal). If your live_edr.py already logs predictions to
structured JSON, use load_from_json_log() instead of the CSV loader.

Usage:
  python3 model_evaluation.py --csv test_set_with_predictions.csv
  python3 model_evaluation.py --json edr_predictions.jsonl
"""
import argparse
import json
import csv
from sklearn.metrics import (
    precision_score, recall_score, f1_score, confusion_matrix,
    accuracy_score, classification_report
)


def load_from_csv(path):
    y_true, y_pred = [], []
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            y_true.append(int(row["true_label"]))
            y_pred.append(int(row["predicted_label"]))
    return y_true, y_pred


def load_from_json(path):
    """Expects each line: {"true_label": 0/1, "predicted_label": 0/1, ...}"""
    y_true, y_pred = [], []
    with open(path) as f:
        for line in f:
            if not line.strip():
                continue
            entry = json.loads(line)
            y_true.append(int(entry["true_label"]))
            y_pred.append(int(entry["predicted_label"]))
    return y_true, y_pred


def evaluate(y_true, y_pred, model_name="EDR Anomaly Model"):
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    accuracy = accuracy_score(y_true, y_pred)
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

    false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    results = {
        "model_name": model_name,
        "n_samples": len(y_true),
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "confusion_matrix": {
            "true_negative": int(tn), "false_positive": int(fp),
            "false_negative": int(fn), "true_positive": int(tp),
        },
    }
    return results


def print_report(results, y_true, y_pred):
    print(f"\n=== {results['model_name']} Evaluation ===")
    print(f"Samples evaluated : {results['n_samples']}")
    print(f"Accuracy          : {results['accuracy']*100:.2f}%")
    print(f"Precision         : {results['precision']*100:.2f}%")
    print(f"Recall            : {results['recall']*100:.2f}%")
    print(f"F1 Score          : {results['f1_score']*100:.2f}%")
    print(f"False Positive Rate: {results['false_positive_rate']*100:.2f}%")
    print("\nConfusion Matrix:")
    cm = results["confusion_matrix"]
    print(f"                 Predicted Normal   Predicted Attack")
    print(f"Actual Normal    {cm['true_negative']:>16}   {cm['false_positive']:>16}")
    print(f"Actual Attack    {cm['false_negative']:>16}   {cm['true_positive']:>16}")
    print("\nFull classification report:")
    print(classification_report(y_true, y_pred, target_names=["Normal", "Attack"], zero_division=0))


def generate_html_snippet(results):
    cm = results["confusion_matrix"]
    return f"""
    <section>
      <h2>ML Model Performance — {results['model_name']}</h2>
      <p>Evaluated on {results['n_samples']} labeled samples (simulated attack + normal traffic).</p>
      <table border="1" cellpadding="6" style="border-collapse:collapse">
        <tr style="background:#1F4E5F;color:white"><th>Metric</th><th>Value</th></tr>
        <tr><td>Accuracy</td><td>{results['accuracy']*100:.2f}%</td></tr>
        <tr><td>Precision</td><td>{results['precision']*100:.2f}%</td></tr>
        <tr><td>Recall</td><td>{results['recall']*100:.2f}%</td></tr>
        <tr><td>F1 Score</td><td>{results['f1_score']*100:.2f}%</td></tr>
        <tr><td>False Positive Rate</td><td>{results['false_positive_rate']*100:.2f}%</td></tr>
      </table>
      <p>Confusion matrix — TP: {cm['true_positive']}, TN: {cm['true_negative']},
      FP: {cm['false_positive']}, FN: {cm['false_negative']}</p>
    </section>
    """


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", help="CSV with true_label, predicted_label columns")
    ap.add_argument("--json", help="JSONL with true_label, predicted_label fields")
    ap.add_argument("--model-name", default="EDR Anomaly Model (Isolation Forest + Random Forest)")
    ap.add_argument("--html-out", help="Optional: write HTML snippet to this file")
    args = ap.parse_args()

    if args.csv:
        y_true, y_pred = load_from_csv(args.csv)
    elif args.json:
        y_true, y_pred = load_from_json(args.json)
    else:
        raise SystemExit("Provide --csv or --json")

    results = evaluate(y_true, y_pred, args.model_name)
    print_report(results, y_true, y_pred)

    if args.html_out:
        with open(args.html_out, "w") as f:
            f.write(generate_html_snippet(results))
        print(f"\nHTML snippet written to {args.html_out}")
