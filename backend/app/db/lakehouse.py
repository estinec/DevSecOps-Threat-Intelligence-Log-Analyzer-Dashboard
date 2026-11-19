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


def read_latest_silver_events(
    silver_dir: str | Path = "backend/data/lakehouse/silver",
) -> List[NormalizedEvent]:
    directory = Path(silver_dir)
    if not directory.exists():
        return []

    parquet_files = sorted(directory.glob("silver_*.parquet"))
    if not parquet_files:
        return []

    latest_file = parquet_files[-1]
    with duckdb.connect(database=":memory:") as con:
        rel = con.execute(f'SELECT * FROM read_parquet("{latest_file}")')
        columns = [desc[0] for desc in rel.description]
        records = [dict(zip(columns, row)) for row in rel.fetchall()]

    return [NormalizedEvent.model_validate(record) for record in records]


def query_parquet(sql: str) -> List[tuple]:
    with duckdb.connect(database=":memory:") as con:
        return con.execute(sql).fetchall()


def write_dlq_parquet(
    dead_letter_lines: Iterable[str],
    source_name: str,
    output_dir: str | Path = "backend/data/lakehouse/dlq",
) -> Path:
    dlq_dir = Path(output_dir)
    dlq_dir.mkdir(parents=True, exist_ok=True)

    rejected_at = datetime.now(timezone.utc).isoformat()
    rows: List[Dict[str, Any]] = [
        {
            "raw_line": line,
            "source_name": source_name,
            "rejected_at": rejected_at,
        }
        for line in dead_letter_lines
    ]

    timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = dlq_dir / f"dlq_{timestamp_slug}.parquet"

    if rows:
        table = pa.Table.from_pylist(rows)
        pq.write_table(table, out_path)

    return out_path


def read_latest_dlq_lines(
    dlq_dir: str | Path = "backend/data/lakehouse/dlq",
) -> List[Dict[str, Any]]:
    directory = Path(dlq_dir)
    if not directory.exists():
        return []

    parquet_files = sorted(directory.glob("dlq_*.parquet"))
    if not parquet_files:
        return []

    latest_file = parquet_files[-1]
    rows = query_parquet(
        f'SELECT raw_line, source_name, rejected_at FROM read_parquet("{latest_file}")'
    )

    return [
        {
            "raw_line": r[0],
            "source_name": r[1],
            "rejected_at": r[2],
        }
        for r in rows
    ]
