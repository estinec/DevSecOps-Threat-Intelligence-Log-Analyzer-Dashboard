from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, Query

from app.analytics.gold import build_ip_summary_rows
from app.detections.rules import run_detections
from app.ingestion.pipeline import ingest_log_file

DEFAULT_SAMPLE_LOG = Path(__file__).resolve().parent.parent / "sample_logs" / "sample_access.log"

app = FastAPI(title="DevSecOps Threat Intelligence & Log Analyzer API")


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/summary")
def get_summary(log_path: str = str(DEFAULT_SAMPLE_LOG)) -> List[Dict[str, Any]]:
    result = ingest_log_file(log_path)
    return build_ip_summary_rows(result.valid_events)


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
