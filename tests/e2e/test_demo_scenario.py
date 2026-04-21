from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from backend.app.main import app


ROOT = Path(__file__).resolve().parents[2]


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_demo_scenario_endpoints_cover_phishing_to_exfiltration():
    client = TestClient(app)

    sysmon_records = _load_jsonl(ROOT / "data" / "sample_logs" / "sysmon_attack_chain.jsonl")
    evtx_records = _load_jsonl(ROOT / "data" / "sample_logs" / "evtx_process_events.jsonl")
    pcap_records = json.loads((ROOT / "data" / "pcaps" / "lateral_movement_metadata.json").read_text(encoding="utf-8"))["flows"]

    for source, artifact_id, records in (
        ("sysmon", "sysmon-chain-1", sysmon_records),
        ("evtx", "evtx-events-1", evtx_records),
        ("pcap", "pcap-meta-1", pcap_records),
    ):
        response = client.post(
            "/api/v1/ingest",
            json={
                "investigation_id": "demo-phishing-001",
                "source": source,
                "artifacts": [
                    {
                        "artifact_id": artifact_id,
                        "artifact_type": "jsonl" if source != "pcap" else "json",
                        "content_type": "application/json",
                        "records": records,
                    }
                ],
            },
        )
        assert response.status_code in (200, 202), response.text

    timeline_response = client.get("/api/v1/timeline", params={"investigation_id": "demo-phishing-001"})
    assert timeline_response.status_code == 200, timeline_response.text
    timeline_payload = timeline_response.json()
    assert "entries" in timeline_payload
    serialized_timeline = json.dumps(timeline_payload).lower()
    assert "credential_access" in serialized_timeline or "lateral_movement" in serialized_timeline or "exfiltration" in serialized_timeline

    alerts_response = client.get("/api/v1/alerts", params={"investigation_id": "demo-phishing-001"})
    assert alerts_response.status_code == 200, alerts_response.text
    alerts_payload = alerts_response.json()
    alerts = alerts_payload.get("items", alerts_payload if isinstance(alerts_payload, list) else [])
    assert alerts

    serialized_alerts = json.dumps(alerts).lower()
    assert "credential" in serialized_alerts or "lsass" in serialized_alerts
    assert "lateral" in serialized_alerts or "service" in serialized_alerts

    first_alert_id = alerts[0].get("alert_id") if isinstance(alerts[0], dict) else getattr(alerts[0], "alert_id")
    explanation_response = client.get(f"/api/v1/alerts/{first_alert_id}/explanation")
    assert explanation_response.status_code == 200, explanation_response.text
    explanation_payload = explanation_response.json()
    assert "reason" in json.dumps(explanation_payload).lower() or "next_steps" in explanation_payload