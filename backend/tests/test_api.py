from pathlib import Path
from fastapi.testclient import TestClient

import app.main as main_module
from app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_summary_endpoint():
    response = client.get("/summary")
    assert response.status_code == 200
    rows = response.json()
    assert len(rows) == 4
    by_ip = {row["source_ip"]: row for row in rows}
    assert by_ip["203.0.113.25"]["total_requests"] == 5
    assert by_ip["203.0.113.25"]["failed_logins"] == 5


def test_alerts_endpoint_with_custom_thresholds():
    response = client.get(
        "/alerts",
        params={"failed_login_threshold": 2, "request_volume_threshold": 5},
    )
    assert response.status_code == 200
    alerts = response.json()
    rule_ids = [alert["rule_id"] for alert in alerts]
    assert rule_ids == ["RULE-AUTH-001", "RULE-VOL-001"]


def test_post_ingest_raw_lines_writes_parquet_and_returns_alerts(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(main_module, "LAKEHOUSE_ROOT", tmp_path / "lakehouse")

    response = client.post(
        "/ingest",
        json={
            "source_name": "test_stream.log",
            "raw_lines": [
                '203.0.113.25 - - [17/Nov/2026:14:25:30 +0000] "POST /login HTTP/1.1" 401 512 "DemoClient/1.0"',
                '203.0.113.25 - - [17/Nov/2026:14:25:31 +0000] "POST /login HTTP/1.1" 401 512 "DemoClient/1.0"',
                "malformed_log_line",
            ],
            "failed_login_threshold": 2,
            "request_volume_threshold": 2,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["counts"] == {
        "raw_lines": 3,
        "valid_events": 2,
        "dead_letter_lines": 1,
        "alerts": 2,
    }
    assert Path(body["artifacts"]["bronze_parquet"]).exists()
    assert Path(body["artifacts"]["silver_parquet"]).exists()
    assert Path(body["artifacts"]["gold_parquet"]).exists()
    assert [alert["rule_id"] for alert in body["alerts"]] == ["RULE-AUTH-001", "RULE-VOL-001"]


def test_post_ingest_requires_source():
    response = client.post("/ingest", json={})
    assert response.status_code == 400
