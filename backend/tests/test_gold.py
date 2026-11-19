from datetime import datetime, timezone
from pathlib import Path

from app.analytics.gold import build_ip_summary_rows, write_gold_ip_summary_parquet
from app.db.lakehouse import query_parquet
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


def test_build_ip_summary_rows_aggregates_metrics():
    events = [
        _make_event("203.0.113.25", "POST", "/login", 401, "failure"),
        _make_event("203.0.113.25", "POST", "/login", 401, "failure"),
        _make_event("203.0.113.25", "GET", "/admin", 403, None),
        _make_event("192.168.1.10", "GET", "/health", 500, None),
    ]

    rows = build_ip_summary_rows(events)

    assert rows == [
        {
            "source_ip": "192.168.1.10",
            "total_requests": 1,
            "failed_logins": 0,
            "client_errors_4xx": 0,
            "server_errors_5xx": 1,
        },
        {
            "source_ip": "203.0.113.25",
            "total_requests": 3,
            "failed_logins": 2,
            "client_errors_4xx": 3,
            "server_errors_5xx": 0,
        },
    ]


def test_write_gold_ip_summary_parquet_persists_rows(tmp_path: Path):
    events = [
        _make_event("10.0.0.5", "GET", "/index.html", 200, None),
        _make_event("10.0.0.5", "POST", "/login", 401, "failure"),
    ]

    gold_file = write_gold_ip_summary_parquet(events=events, output_dir=tmp_path)
    assert gold_file.exists()

    rows = query_parquet(
        f'SELECT source_ip, total_requests, failed_logins FROM read_parquet("{gold_file}")'
    )
    assert rows == [("10.0.0.5", 2, 1)]
