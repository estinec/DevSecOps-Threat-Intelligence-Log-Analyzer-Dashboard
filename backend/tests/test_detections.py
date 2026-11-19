from datetime import datetime, timezone

from app.detections.rules import (
    detect_failed_login_bursts,
    detect_high_request_volume,
    run_detections,
)
from app.schemas.event import NormalizedEvent


def _make_event(
    ip: str,
    method: str = "GET",
    path: str = "/index.html",
    status_code: int = 200,
    auth_result: str | None = None,
) -> NormalizedEvent:
    raw = f'{ip} - - [17/Nov/2026:14:20:00 +0000] "{method} {path} HTTP/1.1" {status_code} 200 "Mozilla/5.0"'
    return NormalizedEvent(
        timestamp=datetime(2026, 11, 17, 14, 20, 0, tzinfo=timezone.utc),
        source_ip=ip,
        event_type="http_access",
        method=method,
        path=path,
        status_code=status_code,
        user_agent="Mozilla/5.0",
        auth_result=auth_result,
        raw_line=raw,
    )


def test_detect_failed_login_bursts_triggers_at_threshold():
    events = [
        _make_event("203.0.113.25", "POST", "/login", 401, "failure"),
        _make_event("203.0.113.25", "POST", "/login", 401, "failure"),
        _make_event("192.168.1.10", "POST", "/login", 401, "failure"),
    ]

    alerts = detect_failed_login_bursts(events, threshold=2)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-AUTH-001"
    assert alerts[0].severity == "high"
    assert alerts[0].source_ip == "203.0.113.25"
    assert alerts[0].event_count == 2


def test_detect_high_request_volume_triggers_at_threshold():
    events = [_make_event("10.0.0.5") for _ in range(3)] + [_make_event("192.168.1.10")]

    alerts = detect_high_request_volume(events, threshold=3)

    assert len(alerts) == 1
    assert alerts[0].rule_id == "RULE-VOL-001"
    assert alerts[0].severity == "medium"
    assert alerts[0].source_ip == "10.0.0.5"
    assert alerts[0].event_count == 3


def test_run_detections_combines_alerts():
    events = [
        _make_event("203.0.113.25", "POST", "/login", 401, "failure"),
        _make_event("203.0.113.25", "POST", "/login", 401, "failure"),
    ]

    alerts = run_detections(events, failed_login_threshold=2, request_volume_threshold=2)
    rule_ids = [alert.rule_id for alert in alerts]

    assert rule_ids == ["RULE-AUTH-001", "RULE-VOL-001"]
