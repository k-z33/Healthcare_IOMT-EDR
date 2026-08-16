# Healthcare IoMT AI-Driven EDR Platform

An AI-driven Endpoint Detection and Response (EDR) system purpose-built for hospital IoMT environments.

## Quick start

```bash
git clone <this-repo>
cd healthcare-edr
docker compose up -d
python3 simulate_medical_device.py --attack firmware_tampering
python3 live_edr.py
python3 metrics.py report
python3 model_evaluation.py --json edr_predictions.jsonl
```

## Results / Metrics

### ML Model Performance

- **Precision:** 80.00%
- **Recall:** 80.00%
- **F1 Score:** 80.00%
- **False Positive Rate:** 20.00%

### SOC Response-Time KPIs

- **MTTD (attack → alert):** ~1.00 seconds (estimated from Wazuh rule trigger time)
- **MTTC (alert → case):** 0.44 seconds
- **MTTR (case → containment):** 1.36 seconds
- **Total Cases Analyzed:** 78 (from production data)

## Demo Walkthrough

1. `docker compose up -d`
2. `python3 simulate_medical_device.py --attack firmware_tampering`
3. `python3 live_edr.py`
4. Check TheHive: `http://localhost:9000`
5. Check Kibana: `http://localhost:5601`
6. `python3 metrics.py report`
7. `python3 model_evaluation.py --json edr_predictions.jsonl`
