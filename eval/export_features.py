"""Render archived C1 feature rows as labeled CSV for B's `ml/train.py`/`evaluate.py`.

The harness archives the observe-mode stream as ``<run>/features.jsonl`` (one JSON
object per line, exactly what Redis returned). B's tooling reads CSV, so the handoff
also needs the same rows as a CSV with a ``label`` column joined from
``labels.json`` (``run_id -> source IP -> benign/attack``).

    python3 eval/export_features.py --runs eval/runs --labels eval/labels.json \
        --out-dir eval/handoff/features-csv

A missing label becomes ``unknown`` rather than being guessed: ``ml/export.py`` uses
the same convention, and training must not silently learn from an unlabeled row.
Empty or absent feature files are skipped, and the exit status is non-zero when no run
carries an export.
"""

from __future__ import annotations

import argparse
import csv
import json
import pathlib
import sys

# Identity columns first so a human opening the file sees the keys before the features.
META_COLUMNS = ("stream_id", "run_id", "ip", "label", "feature_version",
                "ts_ms", "method", "route")


def load_labels(path: pathlib.Path | None) -> dict:
    if path is None or not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def read_rows(feature_file: pathlib.Path) -> list[dict]:
    rows = []
    with feature_file.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def columns_for(rows: list[dict]) -> list[str]:
    present = set().union(*(row.keys() for row in rows))
    meta = [name for name in META_COLUMNS if name in present]
    return meta + sorted(present - set(meta))


def export(runs_dir: pathlib.Path, labels_path: pathlib.Path | None,
           out_dir: pathlib.Path) -> list[pathlib.Path]:
    labels = load_labels(labels_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[pathlib.Path] = []
    for run_dir in sorted(path for path in runs_dir.iterdir() if path.is_dir()):
        feature_file = run_dir / "features.jsonl"
        if not feature_file.is_file() or feature_file.stat().st_size == 0:
            continue
        rows = read_rows(feature_file)
        if not rows:
            continue
        by_ip = labels.get(run_dir.name, {})
        for row in rows:
            row["label"] = by_ip.get(row.get("ip"), "unknown")
        columns = columns_for(rows)
        output = out_dir / f"{run_dir.name}.csv"
        with output.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, restval="",
                                    lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        written.append(output)
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runs", default="eval/runs")
    parser.add_argument("--labels", default="eval/labels.json",
                        help="labels.json from eval/labels.py; omit to label rows 'unknown'")
    parser.add_argument("--out-dir", default="eval/handoff/features-csv")
    args = parser.parse_args()
    runs_dir = pathlib.Path(args.runs)
    if not runs_dir.is_dir():
        print(f"no run directory at {runs_dir}", file=sys.stderr)
        return 2
    labels_path = pathlib.Path(args.labels) if args.labels else None
    written = export(runs_dir, labels_path, pathlib.Path(args.out_dir))
    for path in written:
        with path.open(encoding="utf-8") as handle:
            rows = max(0, sum(1 for _ in handle) - 1)
        print(f"{path}: {rows} row(s)")
    if not written:
        print("no run has a non-empty features.jsonl export", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
