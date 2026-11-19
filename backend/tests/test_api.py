from fastapi.testclient import TestClient

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
