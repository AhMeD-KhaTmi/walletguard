"""The handoff must ship the same rows as CSV with labels joined, not guessed."""

import csv
import json

from eval import export_features


def write_run(root, run_id, rows):
    run = root / run_id
    run.mkdir()
    with (run / "features.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
    return run


def write_labels(root, mapping):
    path = root / "labels.json"
    path.write_text(json.dumps(mapping), encoding="utf-8")
    return path


def read_csv(path):
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def test_csv_rows_carry_the_joined_label_and_keep_identity_columns_first(tmp_path):
    runs = tmp_path / "runs"
    runs.mkdir()
    write_run(runs, "c1-benign-f1", [
        {"stream_id": "1-0", "run_id": "c1-benign-f1", "ip": "10.20.0.11",
         "feature_version": "2", "is_chat": "0", "req_10s": "3"},
        {"stream_id": "2-0", "run_id": "c1-benign-f1", "ip": "10.20.0.19",
         "feature_version": "2", "is_chat": "1", "req_10s": "4"},
    ])
    labels = write_labels(tmp_path, {"c1-benign-f1": {"10.20.0.11": "benign"}})
    written = export_features.export(runs, labels, tmp_path / "out")
    assert [path.name for path in written] == ["c1-benign-f1.csv"]
    rows = read_csv(written[0])
    assert list(rows[0])[:5] == ["stream_id", "run_id", "ip", "label", "feature_version"]
    assert rows[0]["label"] == "benign"
    # An address missing from labels.json stays explicit instead of being guessed.
    assert rows[1]["label"] == "unknown"
    assert rows[0]["req_10s"] == "3"


def test_empty_and_missing_feature_files_are_skipped(tmp_path):
    runs = tmp_path / "runs"
    runs.mkdir()
    (runs / "empty").mkdir()
    (runs / "empty" / "features.jsonl").write_text("", encoding="utf-8")
    (runs / "pre-archive").mkdir()
    (runs / "pre-archive" / "manifest.json").write_text("{}", encoding="utf-8")
    write_run(runs, "c1-scraping-f1", [
        {"stream_id": "1-0", "run_id": "c1-scraping-f1", "ip": "10.20.0.19"}])
    written = export_features.export(runs, None, tmp_path / "out")
    assert [path.name for path in written] == ["c1-scraping-f1.csv"]
    # Without a labels file the row is still exported, labelled unknown.
    assert read_csv(written[0])[0]["label"] == "unknown"


def test_no_feature_exports_writes_nothing_and_reports_failure(tmp_path):
    runs = tmp_path / "runs"
    runs.mkdir()
    (runs / "pre-archive").mkdir()
    (runs / "pre-archive" / "manifest.json").write_text("{}", encoding="utf-8")
    assert export_features.export(runs, None, tmp_path / "out") == []
