import glob, yaml, json

enterprise = {}
ics = {}

for f in glob.glob("*.yml"):
    try:
        d = yaml.safe_load(open(f))
        for t in d.get("tags", []):
            if t.startswith("attack.t"):
                tid = t.replace("attack.t", "T").upper()
                if tid.startswith("T0") and len(tid) == 5:  # T0xxx = ICS
                    ics[tid] = ics.get(tid, 0) + 1
                else:  # T1xxx = Enterprise
                    enterprise[tid] = enterprise.get(tid, 0) + 1
    except Exception as e:
        print(f"Skip {f}: {e}")

def make_layer(techniques, domain, name):
    return {
        "name": name,
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": domain,
        "description": f"Coverage map of IoMT EDR Sigma rules ({domain})",
        "techniques": [
            {"techniqueID": tid, "score": count, "comment": f"{count} rule(s)"}
            for tid, count in sorted(techniques.items())
        ],
        "gradient": {
            "colors": ["#ffffff", "#66b1ff", "#1a5276"],
            "minValue": 0,
            "maxValue": max(techniques.values()) if techniques else 1
        },
        "legendItems": [{"label": "Covered", "color": "#66b1ff"}]
    }

with open("navigator_layer_enterprise.json", "w") as f:
    json.dump(make_layer(enterprise, "enterprise-attack", "IoMT EDR Coverage - Enterprise"), f, indent=2)

with open("navigator_layer_ics.json", "w") as f:
    json.dump(make_layer(ics, "ics-attack", "IoMT EDR Coverage - ICS"), f, indent=2)

print(f"Enterprise: {len(enterprise)} techniques → navigator_layer_enterprise.json")
print("  ", ", ".join(sorted(enterprise.keys())))
print(f"ICS: {len(ics)} techniques → navigator_layer_ics.json")
print("  ", ", ".join(sorted(ics.keys())))
