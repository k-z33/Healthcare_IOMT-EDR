# Kibana Dashboard — Build Steps (Healthcare IoMT EDR)

These are manual UI steps rather than an auto-import file, because Kibana's
saved-object NDJSON format is version-specific and an untested import file
can silently fail. These steps work in any recent Kibana version.

**Prerequisite:** `index_alerts_to_es.py` has run at least once (so the
`iomt-alerts` index has data) and `create_index_pattern.sh` has run.

---

## Visualization 1 — Alerts by Severity (Pie Chart)

1. Kibana UI → **Visualize Library** → **Create visualization** → **Lens**
2. Index pattern: `iomt-alerts*`
3. Chart type: **Pie**
4. Slice by: `severity` (terms aggregation)
5. Size by: **Count of records**
6. Save as: `IoMT — Alerts by Severity`

## Visualization 2 — Alerts by Device (Bar Chart)

1. **Visualize Library** → **Create visualization** → **Lens**
2. Index pattern: `iomt-alerts*`
3. Chart type: **Bar vertical**
4. Horizontal axis: `device_id` (terms, top 10)
5. Vertical axis: **Count of records**
6. Save as: `IoMT — Alerts by Device`

## Visualization 3 — Alert Volume Over Time (KPI trend, Phase 3.6)

1. **Visualize Library** → **Create visualization** → **Lens**
2. Index pattern: `iomt-alerts*`
3. Chart type: **Line**
4. Horizontal axis: `@timestamp` (date histogram, auto interval)
5. Vertical axis: **Count of records**, broken down by `severity`
6. Save as: `IoMT — Alert Volume Over Time`

## Visualization 4 — Patient-Safety vs Non-Critical Split

1. **Visualize Library** → **Create visualization** → **Lens**
2. Index pattern: `iomt-alerts*`
3. Chart type: **Donut**
4. Slice by: `device_id` (terms) — group patient-safety devices
   (ventilator*, infusion-pump*, patient-monitor*) visually against the rest
   using a Kibana **Filter** per slice, or add a scripted field
   `is_patient_safety_device` in Index Pattern management if you want a
   clean single field (Stack Management → Index Patterns → iomt-alerts* →
   Add field → Painless script):
   ```painless
   String d = doc['device_id.keyword'].value;
   return d.startsWith('ventilator') || d.startsWith('infusion-pump') || d.startsWith('patient-monitor');
   ```
5. Save as: `IoMT — Patient-Safety Device Split`

---

## Assemble the Dashboard

1. **Dashboard** → **Create dashboard**
2. **Add from library** → add all 4 visualizations above
3. Arrange in a 2x2 grid
4. Save as: `Healthcare IoMT EDR — Overview`
5. Set the time picker (top right) to **Last 24 hours** as default, save
   again with "Store time with dashboard" checked

---

## Verify data is flowing

```bash
curl -s "http://localhost:9200/iomt-alerts/_count" | python3 -m json.tool
```
Should show a non-zero `count`. If it's 0, re-run `index_alerts_to_es.py`
on the Manager box first.
