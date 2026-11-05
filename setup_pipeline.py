"""Create and validate the Toloka review pipeline."""

import csv
import json
import os
import time
from pathlib import Path

from dotenv import load_dotenv

from phishguard.toloka import TolokaClient

ROOT = Path(__file__).resolve().parent
CONFIG = ROOT / ".local/provider-setup.json"


def main() -> None:
    load_dotenv(ROOT / ".env")
    for name in (
        "LLM_API_KEY",
        "TOLOKA_API_KEY",
        "TENDEM_API_KEY",
        "LLM_BASE_URL",
        "LLM_MODEL",
    ):
        if not os.getenv(name, "").strip():
            raise ValueError(f"Set {name} in .env before setup")
    api = TolokaClient(os.environ["TOLOKA_API_KEY"])
    config = json.loads(CONFIG.read_text(encoding="utf-8")) if CONFIG.exists() else {}

    def save():
        CONFIG.parent.mkdir(parents=True, exist_ok=True)
        CONFIG.write_text(json.dumps(config, indent=2), encoding="utf-8")

    if not config.get("project_id"):
        projects = api.request("GET", "/projects")["projects"]
        matching = [
            p
            for p in projects
            if p["name"] == "Signal security review" and p["status"] == "active"
        ]
        if len(matching) == 1:
            project = matching[0]
        else:
            teams = {p["teamId"] for p in projects}
            team_id = os.getenv("TOLOKA_TEAM_ID") or (
                next(iter(teams)) if len(teams) == 1 else None
            )
            if not team_id:
                raise ValueError(
                    "Set TOLOKA_TEAM_ID to the team that should own this prototype"
                )
            project = api.request(
                "POST",
                "/projects",
                {"teamId": team_id, "name": "Signal security review"},
            )
        config["project_id"] = project["id"]
        save()
    if not config.get("dataset_id"):
        dataset = api.request(
            "POST",
            f"/projects/{config['project_id']}/datasets",
            {"name": "Signal independent review"},
        )
        config["dataset_id"] = dataset["id"]
        save()
    existing = api.request("GET", f"/datasets/{config['dataset_id']}/items")[
        "pagination"
    ]["total"]
    if existing == 0:
        with (ROOT / "data/synthetic_cases.csv").open(
            encoding="utf-8", newline=""
        ) as file:
            rows = list(csv.DictReader(file))[:3]
        api.request(
            "POST",
            f"/datasets/{config['dataset_id']}/items",
            {
                "fields": [
                    {"name": n, "jsonSchema": {"type": "string"}}
                    for n in ("case_id", "email_text")
                ],
                "items": [
                    {
                        "case_id": r["id"],
                        "email_text": f"From: {r['sender']}\nSubject: {r['subject']}\n\n{r['body']}",
                    }
                    for r in rows
                ],
            },
        )
    elif existing != 3:
        raise ValueError(
            "The seed dataset has an unexpected number of rows; inspect before continuing"
        )
    if not config.get("pipeline_id"):
        graph = json.loads(
            (ROOT / "data/toloka_pipeline.json").read_text(encoding="utf-8")
        )
        pipeline = api.request(
            "POST",
            f"/projects/{config['project_id']}/pipelines/import",
            {
                "name": "Signal independent email review",
                "graph": graph,
            },
        )
        config["pipeline_id"] = pipeline["id"]
        save()
    runs = api.request("GET", f"/pipelines/{config['pipeline_id']}/runs")
    if runs.get("runs"):
        print(
            "This pipeline already has a run. Existing work is retained; setup will not modify it."
        )
        return
    api.request(
        "POST",
        f"/pipelines/{config['pipeline_id']}/dataset",
        {"datasetId": config["dataset_id"], "itemLimit": 3},
    )
    api.request("POST", f"/pipelines/{config['pipeline_id']}/lints", {})
    for attempt in range(15):
        try:
            api.validate(config["pipeline_id"])
            break
        except ValueError:
            if attempt == 14:
                raise
            time.sleep(3)
    estimate = api.estimate(config["pipeline_id"])
    print("Toloka pipeline ready. Forecast:", estimate["total"])
    print(
        "Pipeline setup is complete. Start Signal to let the agent coordinate the investigation."
    )


if __name__ == "__main__":
    main()
