from datetime import datetime
import re
from typing import Optional

from app.schemas.event import NormalizedEvent


LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+[^"]+"\s+'
    r'(?P<status>\d{3})\s+\S+\s+'
    r'"(?P<user_agent>[^"]*)"'
)


def parse_access_line(line: str) -> Optional[NormalizedEvent]:
    cleaned = line.strip()
    if not cleaned:
        return None

    match = LOG_PATTERN.match(cleaned)
    if not match:
        return None

    try:
        parsed_ts = datetime.strptime(match.group("timestamp"), "%d/%b/%Y:%H:%M:%S %z")
        status_code = int(match.group("status"))
    except ValueError:
        return None

    auth_result = None
    if match.group("path") == "/login":
        auth_result = "success" if status_code == 200 else "failure"

    return NormalizedEvent(
        timestamp=parsed_ts,
        source_ip=match.group("ip"),
        event_type="http_access",
        method=match.group("method"),
        path=match.group("path"),
        status_code=status_code,
        user_agent=match.group("user_agent") or None,
        auth_result=auth_result,
        raw_line=cleaned,
    )
