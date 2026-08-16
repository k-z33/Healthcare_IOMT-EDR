"""
MISP Integration (EDR SOAR Module)
Wazuh / ML alerts → MISP IOC push
"""

import requests
import json
from datetime import datetime

# ✅ FIX 1: correct URL
MISP_URL = "https://localhost:8443"
MISP_KEY = "YOUR_MISP_API_KEY"

HEADERS = {
    "Authorization": MISP_KEY,
    "Content-Type": "application/json",
    "Accept": "application/json"
}

def test_connection():
    """Check MISP connectivity"""
    try:
        r = requests.get(
            f"{MISP_URL}/users/view/me",
            headers=HEADERS,
            verify=False,
            timeout=5
        )
        print("Connection Status:", r.status_code)
        print("Response:", r.text[:200])
    except Exception as e:
        print("MISP not reachable:", e)


def create_event():
    """Create EDR event in MISP"""
    event = {
        "Event": {
            "info": "EDR Automated Threat Event",
            "date": str(datetime.now().date()),
            "analysis": 1,
            "threat_level_id": 2,
            "Attribute": [
                {
                    "type": "ip-src",
                    "value": "192.168.1.100",
                    "comment": "Suspicious source IP from ML detection"
                },
                {
                    "type": "filename",
                    "value": "ransomware.exe",
                    "comment": "Detected by Isolation Forest"
                }
            ]
        }
    }

    try:
        r = requests.post(
            f"{MISP_URL}/events/add",
            headers=HEADERS,
            data=json.dumps(event),
            verify=False
        )

        print("Response Code:", r.status_code)
        print("Response:", r.text[:300])

    except Exception as e:
        print("Event creation failed:", e)


if __name__ == "__main__":
    print("=== MISP Integration Test ===")
    test_connection()
    create_event()
