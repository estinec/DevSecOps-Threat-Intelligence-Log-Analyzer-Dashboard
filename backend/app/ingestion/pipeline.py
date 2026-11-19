from dataclasses import dataclass
from pathlib import Path
from typing import List

from app.parsers.access_log import parse_access_line
from app.schemas.event import NormalizedEvent


@dataclass
class IngestionResult:
    valid_events: List[NormalizedEvent]
    dead_letter_lines: List[str]


def ingest_log_file(file_path: str | Path) -> IngestionResult:
    path = Path(file_path)
    valid_events: List[NormalizedEvent] = []
    dead_letter_lines: List[str] = []

    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            stripped = raw_line.rstrip("\r\n")
            if not stripped.strip():
                continue

            event = parse_access_line(stripped)
            if event is not None:
                valid_events.append(event)
            else:
                dead_letter_lines.append(stripped)

    return IngestionResult(
        valid_events=valid_events,
        dead_letter_lines=dead_letter_lines,
    )
