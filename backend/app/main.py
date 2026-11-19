from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from app.analytics.gold import (
    build_ip_summary_rows,
    read_latest_gold_ip_summary,
    write_gold_ip_summary_parquet,
)
from app.db.lakehouse import (
    read_latest_silver_events,
    write_bronze_parquet,
    write_silver_parquet,
)
from app.detections.rules import run_detections
from app.ingestion.pipeline import ingest_log_file
from app.parsers.access_log import parse_access_line
from app.schemas.event import NormalizedEvent

DEFAULT_SAMPLE_LOG = Path(__file__).resolve().parent.parent / "sample_logs" / "sample_access.log"
LAKEHOUSE_ROOT = Path(__file__).resolve().parent.parent / "data" / "lakehouse"

app = FastAPI(title="DevSecOps Threat Intelligence & Log Analyzer API")


class IngestRequest(BaseModel):
    log_path: Optional[str] = None
    raw_lines: Optional[List[str]] = None
    source_name: str = "api_ingest"
    failed_login_threshold: int = 3
    request_volume_threshold: int = 5


def _ingest_from_raw_lines(lines: List[str]) -> tuple[List[NormalizedEvent], List[str], List[str]]:
    cleaned_lines: List[str] = []
    valid_events: List[NormalizedEvent] = []
    dead_letter_lines: List[str] = []

    for raw_line in lines:
        stripped = raw_line.rstrip("\r\n")
        if not stripped.strip():
            continue
        cleaned_lines.append(stripped)
        event = parse_access_line(stripped)
        if event is not None:
            valid_events.append(event)
        else:
            dead_letter_lines.append(stripped)

    return cleaned_lines, valid_events, dead_letter_lines


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/summary")
def get_summary(log_path: str = str(DEFAULT_SAMPLE_LOG)) -> List[Dict[str, Any]]:
    result = ingest_log_file(log_path)
    return build_ip_summary_rows(result.valid_events)


@app.get("/lakehouse/summary")
def get_lakehouse_summary() -> List[Dict[str, Any]]:
    rows = read_latest_gold_ip_summary(LAKEHOUSE_ROOT / "gold")
    if not rows:
        raise HTTPException(
            status_code=404,
            detail="No Gold Parquet summary found. Run POST /ingest first.",
        )
    return rows


@app.get("/lakehouse/alerts")
def get_lakehouse_alerts(
    failed_login_threshold: int = Query(default=3, ge=1),
    request_volume_threshold: int = Query(default=5, ge=1),
) -> List[Dict[str, Any]]:
    events = read_latest_silver_events(LAKEHOUSE_ROOT / "silver")
    if not events:
        raise HTTPException(
            status_code=404,
            detail="No Silver Parquet events found. Run POST /ingest first.",
        )
    alerts = run_detections(
        events,
        failed_login_threshold=failed_login_threshold,
        request_volume_threshold=request_volume_threshold,
    )
    return [asdict(alert) for alert in alerts]


@app.get("/alerts")
def get_alerts(
    log_path: str = str(DEFAULT_SAMPLE_LOG),
    failed_login_threshold: int = Query(default=3, ge=1),
    request_volume_threshold: int = Query(default=5, ge=1),
) -> List[Dict[str, Any]]:
    result = ingest_log_file(log_path)
    alerts = run_detections(
        result.valid_events,
        failed_login_threshold=failed_login_threshold,
        request_volume_threshold=request_volume_threshold,
    )
    return [asdict(alert) for alert in alerts]


@app.post("/ingest")
def post_ingest(payload: IngestRequest) -> Dict[str, Any]:
    if payload.log_path:
        path = Path(payload.log_path)
        if not path.exists():
            raise HTTPException(status_code=404, detail=f"Log file not found: {payload.log_path}")
        raw_lines = [
            line.rstrip("\r\n")
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        result = ingest_log_file(path)
        valid_events = result.valid_events
        dead_letter_lines = result.dead_letter_lines
        source_name = path.name
    elif payload.raw_lines is not None:
        raw_lines, valid_events, dead_letter_lines = _ingest_from_raw_lines(payload.raw_lines)
        source_name = payload.source_name
    else:
        raise HTTPException(
            status_code=400,
            detail="Provide either 'log_path' or 'raw_lines' in request body.",
        )

    bronze_path = write_bronze_parquet(
        raw_lines=raw_lines,
        source_name=source_name,
        output_dir=LAKEHOUSE_ROOT / "bronze",
    )
    silver_path = write_silver_parquet(
        events=valid_events,
        output_dir=LAKEHOUSE_ROOT / "silver",
    )
    gold_path = write_gold_ip_summary_parquet(
        events=valid_events,
        output_dir=LAKEHOUSE_ROOT / "gold",
    )

    alerts = run_detections(
        valid_events,
        failed_login_threshold=payload.failed_login_threshold,
        request_volume_threshold=payload.request_volume_threshold,
    )

    return {
        "source_name": source_name,
        "counts": {
            "raw_lines": len(raw_lines),
            "valid_events": len(valid_events),
            "dead_letter_lines": len(dead_letter_lines),
            "alerts": len(alerts),
        },
        "artifacts": {
            "bronze_parquet": str(bronze_path),
            "silver_parquet": str(silver_path),
            "gold_parquet": str(gold_path),
        },
        "alerts": [asdict(alert) for alert in alerts],
    }
