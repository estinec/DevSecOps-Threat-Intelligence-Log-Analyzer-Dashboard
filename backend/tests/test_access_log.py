from app.parsers.access_log import parse_access_line


def test_parse_valid_get_request():
    line = '192.168.1.10 - - [17/Nov/2026:14:20:00 +0000] "GET /index.html HTTP/1.1" 200 2326 "Mozilla/5.0"'
    event = parse_access_line(line)

    assert event is not None
    assert event.source_ip == "192.168.1.10"
    assert event.event_type == "http_access"
    assert event.method == "GET"
    assert event.path == "/index.html"
    assert event.status_code == 200
    assert event.user_agent == "Mozilla/5.0"
    assert event.auth_result is None


def test_parse_failed_login_sets_auth_result():
    line = '203.0.113.25 - - [17/Nov/2026:14:25:30 +0000] "POST /login HTTP/1.1" 401 512 "DemoClient/1.0"'
    event = parse_access_line(line)

    assert event is not None
    assert event.auth_result == "failure"


def test_parse_malformed_line_returns_none():
    assert parse_access_line("not a valid log line") is None
    assert parse_access_line("") is None
