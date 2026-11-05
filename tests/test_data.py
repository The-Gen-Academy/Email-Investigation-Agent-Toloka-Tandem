"""Small dataset contract for the sample dataset and expert labeling workflow."""

import csv
from pathlib import Path


def test_ten_safe_unlabeled_emails():
    path = Path(__file__).parents[1] / "data" / "synthetic_cases.csv"
    with path.open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    assert len(rows) == 10
    assert len({row["id"] for row in rows}) == len(rows)
    assert all(row["sender"] and row["subject"] and row["body"] for row in rows)
    assert all(row["sender"].endswith(".example") for row in rows)
    assert all("label" not in row for row in rows)
