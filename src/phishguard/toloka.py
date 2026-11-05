"""Toloka Pipeline API: validate, price, run, and retrieve human judgments."""

import re
import time
from decimal import Decimal
from urllib.parse import urlsplit

import httpx

LABELS = {"suspicious", "uncertain", "no_obvious_indicators"}


def usd_cents(value: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"\$\d+(?:\.\d{1,2})?", value):
        raise ValueError("Provider quote must be a USD amount, for example $2.59")
    return int(Decimal(value[1:]) * 100)


class TolokaClient:
    BASE = "https://platform.toloka.ai/api/v2-beta"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def request(self, method: str, path: str, body: dict | None = None) -> dict:
        # Retry only read requests; never duplicate a run after a timeout.
        for attempt in range(3):
            with httpx.Client(timeout=30) as client:
                response = client.request(
                    method,
                    self.BASE + path,
                    headers={"Authorization": f"ApiKey {self.api_key}"},
                    json=body if method != "GET" else None,
                )
            if (
                method == "GET"
                and response.status_code in (429, 502, 503, 504)
                and attempt < 2
            ):
                time.sleep(min(10, 2**attempt))
                continue
            if not response.is_success:
                raise RuntimeError(
                    f"Toloka {response.status_code}: {response.text[:1200]}"
                )
            return response.json()
        raise RuntimeError("Toloka unavailable")

    def validate(self, pipeline_id: str) -> dict:
        graph = self.request("GET", f"/pipelines/{pipeline_id}/graph")["graph"]
        report = self.request(
            "POST", f"/pipelines/{pipeline_id}/graph/validate", {"graph": graph}
        )
        blockers = [
            i["message"]
            for i in report["issues"]
            if i["severity"] == "error" or i["code"] == "running_node_check"
        ]
        if blockers:
            raise ValueError("Toloka pipeline is not ready: " + "; ".join(blockers))
        return report

    def estimate(self, pipeline_id: str) -> dict:
        return self.request("POST", f"/pipelines/{pipeline_id}/cost-estimate", {})

    def start(self, pipeline_id: str) -> dict:
        return self.request("POST", f"/pipelines/{pipeline_id}/runs", {})

    def run(self, run_id: str) -> dict:
        return self.request("GET", f"/runs/{run_id}")

    def export(self, dataset_id: str) -> dict:
        return self.request(
            "POST",
            f"/datasets/{dataset_id}/exports",
            {"fields": ["case_id", "label", "rationale"], "format": "json-array"},
        )

    def export_status(self, export_id: str) -> dict:
        return self.request("GET", f"/exports/{export_id}")

    def download_labels(self, url: str, expected_ids: list[str]) -> list[dict]:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or not parsed.hostname.endswith(".blob.core.windows.net")
            or parsed.username
            or parsed.port not in (None, 443)
        ):
            raise ValueError("Toloka returned an invalid export URL")
        # The signed provider URL is fetched without our API key and without redirects.
        with httpx.Client(timeout=30) as client:
            response = client.get(url)
            response.raise_for_status()
            data = response.json()
        if not isinstance(data, list):
            raise ValueError("Toloka dataset export must be an array")
        seen = set()
        for row in data:
            if not isinstance(row, dict) or row.get("case_id") not in expected_ids:
                raise ValueError("Unexpected case in Toloka export")
            if row["case_id"] in seen or row.get("label") not in LABELS:
                raise ValueError("Duplicate case or invalid human label")
            if (
                not isinstance(row.get("rationale"), str)
                or not row["rationale"].strip()
            ):
                raise ValueError("Missing human rationale")
            seen.add(row["case_id"])
        if seen != set(expected_ids):
            raise ValueError("Toloka export is incomplete")
        return data
