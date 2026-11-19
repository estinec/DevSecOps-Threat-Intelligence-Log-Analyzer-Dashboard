from collections import Counter
from dataclasses import dataclass
from typing import Iterable, List

from app.schemas.event import NormalizedEvent


@dataclass(frozen=True)
class ThreatAlert:
    rule_id: str
    severity: str
    source_ip: str
    reason: str
    event_count: int


def detect_failed_login_bursts(
    events: Iterable[NormalizedEvent],
    threshold: int = 3,
) -> List[ThreatAlert]:
    failed_counts: Counter[str] = Counter()

    for event in events:
        if event.auth_result == "failure" or (
            event.path == "/login" and event.status_code in (401, 403)
        ):
            failed_counts[event.source_ip] += 1

    alerts: List[ThreatAlert] = []
    for ip, count in sorted(failed_counts.items()):
        if count >= threshold:
            alerts.append(
                ThreatAlert(
                    rule_id="RULE-AUTH-001",
                    severity="high",
                    source_ip=ip,
                    reason=f"Detected {count} failed login attempts (threshold: {threshold})",
                    event_count=count,
                )
            )
    return alerts


def detect_high_request_volume(
    events: Iterable[NormalizedEvent],
    threshold: int = 5,
) -> List[ThreatAlert]:
    request_counts: Counter[str] = Counter()

    for event in events:
        request_counts[event.source_ip] += 1

    alerts: List[ThreatAlert] = []
    for ip, count in sorted(request_counts.items()):
        if count >= threshold:
            alerts.append(
                ThreatAlert(
                    rule_id="RULE-VOL-001",
                    severity="medium",
                    source_ip=ip,
                    reason=f"Detected {count} requests from single IP (threshold: {threshold})",
                    event_count=count,
                )
            )
    return alerts


def run_detections(
    events: Iterable[NormalizedEvent],
    failed_login_threshold: int = 3,
    request_volume_threshold: int = 5,
) -> List[ThreatAlert]:
    event_list = list(events)
    return [
        *detect_failed_login_bursts(event_list, threshold=failed_login_threshold),
        *detect_high_request_volume(event_list, threshold=request_volume_threshold),
    ]
