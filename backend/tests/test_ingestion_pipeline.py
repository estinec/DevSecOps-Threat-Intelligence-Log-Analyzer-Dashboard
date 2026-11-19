from pathlib import Path

from app.ingestion.pipeline import ingest_log_file


def test_ingest_sample_access_log_returns_valid_events():
    sample_path = Path(__file__).resolve().parent.parent / "sample_logs" / "sample_access.log"
    result = ingest_log_file(sample_path)

    assert len(result.valid_events) == 8
    assert result.dead_letter_lines == []


def test_ingest_mixed_log_separates_dead_letter_lines(tmp_path: Path):
    log_file = tmp_path / "mixed.log"
    log_file.write_text(
        "\n".join([
            '192.168.1.10 - - [17/Nov/2026:14:20:00 +0000] "GET /index.html HTTP/1.1" 200 2326 "Mozilla/5.0"',
            "corrupted line without timestamp or status",
            "",
            '203.0.113.25 - - [17/Nov/2026:14:25:30 +0000] "POST /login HTTP/1.1" 401 512 "DemoClient/1.0"',
            "malformed_entry_123",
        ])
        + "\n",
        encoding="utf-8",
    )

    result = ingest_log_file(log_file)

    assert len(result.valid_events) == 2
    assert result.dead_letter_lines == [
        "corrupted line without timestamp or status",
        "malformed_entry_123",
    ]
