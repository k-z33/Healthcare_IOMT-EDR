#!/usr/bin/env python3
"""
velociraptor_collect.py
Triggers a Velociraptor artifact collection on the Agent client when a
CRITICAL/HIGH case is created, and records the resulting flow in
chain_of_custody.py.

Uses pyvelociraptor (gRPC API) against the Forensics machine.
"""
import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts"))

import yaml
import grpc
from pyvelociraptor import api_pb2
from pyvelociraptor import api_pb2_grpc

# Hardcoded per current environment — Forensics machine, known enrolled Agent client
VELOCIRAPTOR_API_CONFIG = os.path.expanduser("~/velociraptor_api_client.yaml")
AGENT_CLIENT_ID = "C.4dbc16cd0ca01939"   # Agent (172.31.27.110) — confirmed enrolled

# Artifacts to collect on a CRITICAL/HIGH IoMT incident.
# Kept lightweight (metadata + process list) since these are Linux cloud agents,
# not the medical device itself — device telemetry comes via Wazuh, not Velociraptor.
DEFAULT_ARTIFACTS = ["Generic.Client.Info", "Linux.Sys.Pslist", "Linux.Network.Netstat"]


def _load_config(path):
    with open(path, "rt") as fd:
        return yaml.safe_load(fd.read())


def _connect(config):
    creds = grpc.ssl_channel_credentials(
        root_certificates=config["ca_certificate"].encode("utf8"),
        private_key=config["client_private_key"].encode("utf8"),
        certificate_chain=config["client_cert"].encode("utf8"),
    )
    # Server cert CN/SAN is "VelociraptorServer", not the IP address —
    # override the TLS target name so hostname verification passes
    # while still connecting via IP:port.
    options = (("grpc.ssl_target_name_override", "VelociraptorServer"),)
    channel = grpc.secure_channel(config["api_connection_string"], creds, options=options)
    return api_pb2_grpc.APIStub(channel)


def trigger_collection(case_id, device_id=None, artifacts=None, timeout=30):
    """
    Launches a Velociraptor flow on the enrolled Agent client.
    Returns (flow_id, status) — status is 'submitted' or 'error'.
    """
    artifacts = artifacts or DEFAULT_ARTIFACTS
    if not os.path.exists(VELOCIRAPTOR_API_CONFIG):
        print(f"[VELOCIRAPTOR] Config not found: {VELOCIRAPTOR_API_CONFIG}")
        return None, "error"

    try:
        config = _load_config(VELOCIRAPTOR_API_CONFIG)
        stub = _connect(config)

        vql = f"""
        SELECT collect_client(client_id='{AGENT_CLIENT_ID}',
                               artifacts={artifacts},
                               urgent=true) AS Flow
        FROM scope()
        """
        request = api_pb2.VQLCollectorArgs(
            Query=[api_pb2.VQLRequest(VQL=vql)],
            max_wait=1,
        )

        flow_id = None
        for response in stub.Query(request):
            if response.Response:
                import json as _json
                rows = _json.loads(response.Response)
                if rows:
                    flow_id = rows[0].get("Flow", {}).get("flow_id")

        if flow_id:
            print(f"[VELOCIRAPTOR] Collection triggered: flow={flow_id} client={AGENT_CLIENT_ID}")
            try:
                # record_collection() hashes a real local file — but our evidence
                # is a remote Velociraptor flow, not a local file. So we append
                # a CoC-compatible entry directly instead of calling record_collection().
                import json as _json
                import datetime as _dt
                coc_entry = {
                    "event": "collection",
                    "case_id": case_id,
                    "evidence_path": f"velociraptor://{AGENT_CLIENT_ID}/{flow_id}",
                    "evidence_type": "live_triage_collection",
                    "sha256": None,  # not applicable — remote flow, not a local file hash
                    "collector": "velociraptor_collect.py (automated)",
                    "device_id": device_id,
                    "notes": f"Artifacts: {', '.join(artifacts)} | flow_id={flow_id} | client_id={AGENT_CLIENT_ID}",
                    "logged_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                }
                with open("chain_of_custody.jsonl", "a") as f:
                    f.write(_json.dumps(coc_entry) + "\n")
                print(f"[CHAIN-OF-CUSTODY] Logged collection for case={case_id}")
            except Exception as coc_err:
                print(f"[CHAIN-OF-CUSTODY] Warning: could not log — {coc_err}")
            return flow_id, "submitted"
        else:
            print("[VELOCIRAPTOR] No flow_id returned")
            return None, "error"

    except Exception as e:
        print(f"[VELOCIRAPTOR] ERROR triggering collection: {e}")
        return None, "error"


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--device-id", default=None)
    args = ap.parse_args()
    flow_id, status = trigger_collection(args.case_id, args.device_id)
    print(f"Result: flow_id={flow_id} status={status}")
