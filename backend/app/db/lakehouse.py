from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

from app.schemas.event import NormalizedEvent


def write_bronze_parquet(
    raw_lines: Iterable[str],
    source_name: str,
    output_dir: str | Path = "backend/data/lakehouse/bronze",
) -> Path:
    bronze_dir = Path(output_dir)
    bronze_dir.mkdir(parents=True, exist_ok=True)

    ingested_at = datetime.now(timezone.utc).isoformat()
    rows: List[Dict[str, Any]] = [
        {
            "raw_line": line,
            "source_name": source_name,
            "ingested_at": ingested_at,
        }
        for line in raw_lines
    ]

    timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = bronze_dir / f"bronze_{timestamp_slug}.parquet"

    if rows:
        table = pa.Table.from_pylist(rows)
        pq.write_table(table, out_path)

    return out_path


def write_silver_parquet(
    events: Iterable[NormalizedEvent],
    output_dir: str | Path = "backend/data/lakehouse/silver",
) -> Path:
    silver_dir = Path(output_dir)
    silver_dir.mkdir(parents=True, exist_ok=True)

    rows: List[Dict[str, Any]] = []
    for event in events:
        record = event.model_dump()
        if "timestamp" in record and hasattr(record["timestamp"], "isoformat"):
            record["timestamp"] = record["timestamp"].isoformat()
        rows.append(record)

    timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = silver_dir / f"silver_{timestamp_slug}.parquet"

    if rows:
        table = pa.Table.from_pylist(rows)
        pq.write_table(table, out_path)

    return out_path


def query_parquet(sql: str) -> List[tuple]:
    with duckdb.connect(database=":memory:") as con:
        return con.execute(sql).fetchall()
