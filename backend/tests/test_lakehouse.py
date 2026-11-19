from pathlib import Path

from app.db.lakehouse import query_parquet, write_bronze_parquet, write_silver_parquet
from app.ingestion.pipeline import ingest_log_file


def test_write_and_query_bronze_and_silver_parquet(tmp_path: Path):
    sample_path = Path(__file__).resolve().parent.parent / "sample_logs" / "sample_access.log"
    raw_lines = [
        line.rstrip("\r\n")
        for line in sample_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    result = ingest_log_file(sample_path)

    bronze_file = write_bronze_parquet(
        raw_lines=raw_lines,
        source_name="sample_access.log",
        output_dir=tmp_path / "bronze",
    )
    silver_file = write_silver_parquet(
        events=result.valid_events,
        output_dir=tmp_path / "silver",
    )

    assert bronze_file.exists()
    assert silver_file.exists()

    bronze_count = query_parquet(f'SELECT COUNT(*) FROM read_parquet("{bronze_file}")')[0][0]
    silver_rows = query_parquet(
        f'SELECT source_ip, COUNT(*) AS cnt FROM read_parquet("{silver_file}") '
        f'GROUP BY source_ip ORDER BY source_ip'
    )

    assert bronze_count == len(raw_lines)
    assert silver_rows == [
        ("10.0.0.5", 1),
        ("192.168.1.10", 1),
        ("192.168.1.15", 1),
        ("203.0.113.25", 5),
    ]
