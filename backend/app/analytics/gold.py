from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

import pyarrow as pa
import pyarrow.parquet as pq

from app.db.lakehouse import query_parquet
from app.schemas.event import NormalizedEvent


def build_ip_summary_rows(events: Iterable[NormalizedEvent]) -> List[Dict[str, Any]]:
    stats: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "source_ip": "",
            "total_requests": 0,
            "failed_logins": 0,
            "client_errors_4xx": 0,
            "server_errors_5xx": 0,
        }
    )

    for event in events:
        row = stats[event.source_ip]
        row["source_ip"] = event.source_ip
        row["total_requests"] += 1

        if event.auth_result == "failure" or (
            event.path == "/login" and event.status_code in (401, 403)
        ):
            row["failed_logins"] += 1

        if 400 <= event.status_code < 500:
            row["client_errors_4xx"] += 1
        elif 500 <= event.status_code < 600:
            row["server_errors_5xx"] += 1

    return [stats[ip] for ip in sorted(stats.keys())]


def write_gold_ip_summary_parquet(
    events: Iterable[NormalizedEvent],
    output_dir: str | Path = "backend/data/lakehouse/gold",
) -> Path:
    gold_dir = Path(output_dir)
    gold_dir.mkdir(parents=True, exist_ok=True)

    rows = build_ip_summary_rows(events)
    timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = gold_dir / f"gold_ip_summary_{timestamp_slug}.parquet"

    if rows:
        table = pa.Table.from_pylist(rows)
        pq.write_table(table, out_path)

    return out_path


def read_latest_gold_ip_summary(
    gold_dir: str | Path = "backend/data/lakehouse/gold",
) -> List[Dict[str, Any]]:
    directory = Path(gold_dir)
    if not directory.exists():
        return []

    parquet_files = sorted(directory.glob("gold_ip_summary_*.parquet"))
    if not parquet_files:
        return []

    latest_file = parquet_files[-1]
    rows = query_parquet(
        f'SELECT source_ip, total_requests, failed_logins, client_errors_4xx, server_errors_5xx '
        f'FROM read_parquet("{latest_file}") ORDER BY source_ip'
    )

    return [
        {
            "source_ip": r[0],
            "total_requests": r[1],
            "failed_logins": r[2],
            "client_errors_4xx": r[3],
            "server_errors_5xx": r[4],
        }
        for r in rows
    ]
