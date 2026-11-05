"""One local worker connects AI triage, human review, approvals, and results.

The worker survives browser closure while Streamlit is running. SQLite records
each external mutation before it starts, so uncertain outcomes are not replayed.
"""

import csv
import hashlib
import json
import os
import threading
import time
from decimal import Decimal
from pathlib import Path

import httpx

from phishguard import storage
from phishguard.core import Email
from phishguard.investigator import investigate
from phishguard.tendem import TendemClient
from phishguard.toloka import TolokaClient, usd_cents

ROOT = Path(__file__).resolve().parents[2]
REQUIRED = (
    "LLM_API_KEY",
    "TOLOKA_API_KEY",
    "TENDEM_API_KEY",
    "LLM_BASE_URL",
    "LLM_MODEL",
)
SAMPLE_IDS = ["case01", "case02", "case03"]


def cases() -> list[dict]:
    with (ROOT / "data/synthetic_cases.csv").open(encoding="utf-8", newline="") as file:
        return list(csv.DictReader(file))


def fingerprint(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def price_cents(price: dict) -> int:
    if not isinstance(price, dict) or price.get("currency") != "USD":
        raise ValueError("A USD Tendem quote is required")
    amount = Decimal(str(price.get("amount")))
    if (
        not amount.is_finite()
        or amount <= 0
        or amount * 100 != (amount * 100).to_integral_value()
    ):
        raise ValueError("Invalid Tendem quote")
    return int(amount * 100)


class Workflow:
    def __init__(self):
        self.config = {name: os.environ.get(name, "").strip() for name in REQUIRED}
        if any(not v for v in self.config.values()):
            raise ValueError(
                "All three provider keys, model, and base URL are required"
            )
        self.toloka = TolokaClient(self.config["TOLOKA_API_KEY"])
        self.tendem = TendemClient(
            self.config["TENDEM_API_KEY"],
            os.getenv("TENDEM_MCP_URL") or "https://mcp.tendem.ai/mcp",
        )
        self.setup = json.loads(
            (ROOT / ".local/provider-setup.json").read_text(encoding="utf-8")
        )
        self.emails = {r["id"]: r for r in cases()}
        storage.initialize()
        self.stop = threading.Event()
        self.thread = None

    def start(self) -> None:
        self.lock = storage.acquire_worker_lock()
        storage.recover()
        storage.put(
            "ready", {"ok": False, "message": "Checking all three live connections…"}
        )
        storage.enqueue("preflight-" + str(time.time_ns()), "preflight")
        self.thread = threading.Thread(
            target=self._loop, name="signal-worker", daemon=True
        )
        self.thread.start()

    def close(self) -> None:
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=65)
        if hasattr(self, "lock") and (not self.thread or not self.thread.is_alive()):
            self.lock.close()

    def safe_error(self, error: Exception) -> str:
        if isinstance(error, BaseExceptionGroup):
            message = "; ".join(self.safe_error(e) for e in error.exceptions)
        else:
            message = str(error) or type(error).__name__
        for key, value in self.config.items():
            if "KEY" in key and value:
                message = message.replace(value, "[redacted]")
        return message[:1500]

    def _loop(self) -> None:
        next_poll = 0.0
        while not self.stop.is_set():
            command = storage.claim()
            if command:
                try:
                    self.execute(command["kind"], command["payload"])
                    storage.finish(command["id"])
                except Exception as error:
                    message = self.safe_error(error)
                    storage.finish(command["id"], message)
                    storage.event(message)
                    if command["kind"] == "preflight":
                        storage.put("ready", {"ok": False, "message": message})
            if time.time() >= next_poll and storage.get("ready", {}).get("ok"):
                for service, poll in (
                    ("Toloka", self.poll_toloka),
                    ("Tendem", self.poll_tendem),
                ):
                    try:
                        poll()
                        storage.put(service + "_poll_error", None)
                    except Exception as error:
                        storage.put(service + "_poll_error", self.safe_error(error))
                next_poll = time.time() + 30
            self.stop.wait(1)

    def execute(self, kind: str, payload: dict) -> None:
        handlers = {
            "preflight": self.preflight,
            "investigate": self.investigate_batch,
            "approve_toloka": self.approve_toloka,
            "approve_tendem": self.approve_tendem,
            "reply": self.reply,
            "reassess": self.reassess,
        }
        if kind != "preflight" and not storage.get("ready", {}).get("ok"):
            raise ValueError("Resolve the connection or setup error before continuing")
        handlers[kind](payload)

    def preflight(self, payload: dict) -> None:
        with httpx.Client(timeout=25) as client:
            response = client.get(
                self.config["LLM_BASE_URL"].rstrip("/") + "/models",
                headers={"Authorization": "Bearer " + self.config["LLM_API_KEY"]},
            )
            response.raise_for_status()
            if self.config["LLM_MODEL"] not in {
                m["id"] for m in response.json()["data"]
            }:
                raise ValueError("Configured Nebius model is unavailable")
        self.toloka.request("GET", f"/projects/{self.setup['project_id']}/pipelines")
        if not storage.get("toloka", {}).get("run_id"):
            self.toloka.validate(self.setup["pipeline_id"])
        tools = set(self.tendem.tools())
        required = {
            "create_task",
            "get_task",
            "get_contract",
            "approve_task",
            "get_task_result",
            "read_chat",
            "send_message",
        }
        if not required <= tools:
            raise ValueError("Required Tendem tools are unavailable")
        account = self.tendem.call("get_account")
        storage.put(
            "ready",
            {
                "ok": True,
                "checked": storage.now(),
                "model": self.config["LLM_MODEL"],
                "tendem_balance": account["balance"],
                "message": "All three services connected",
            },
        )
        storage.event("Live connections verified: Nebius, Toloka pipeline, Tendem MCP.")

    def analyze(self, case_id: str, expert_evidence: str | None = None) -> dict:
        row = self.emails[case_id]
        answer = investigate(
            Email(row["sender"], row["subject"], row["body"]),
            api_key=self.config["LLM_API_KEY"],
            base_url=self.config["LLM_BASE_URL"],
            model=self.config["LLM_MODEL"],
            synthetic=True,
            expert_evidence=expert_evidence,
        )
        return answer.as_dict() | {
            "time": storage.now(),
            "model": self.config["LLM_MODEL"],
        }

    def investigate_batch(self, payload: dict) -> None:
        from phishguard.agent import InvestigationAgent

        storage.put("batch", {"status": "investigating"})
        InvestigationAgent(self).run()

    def prepare_audit(self, selected: list[str], reason: str) -> None:
        if storage.get("toloka"):
            return
        review = {
            "status": "preparing",
            "sample_ids": selected,
            "selection_reason": reason,
            "pipeline_id": self.setup["pipeline_id"],
            "dataset_id": self.setup["dataset_id"],
        }
        storage.put("toloka", review)
        if set(selected) != set(SAMPLE_IDS):
            dataset = self.toloka.request(
                "POST",
                f"/projects/{self.setup['project_id']}/datasets",
                {"name": "Signal audit " + fingerprint(selected)[:8]},
            )
            review["dataset_id"] = dataset["id"]
            storage.put("toloka", review)
            items = []
            for cid in selected:
                row = self.emails[cid]
                items.append(
                    {
                        "case_id": cid,
                        "email_text": f"From: {row['sender']}\nSubject: {row['subject']}\n\n{row['body']}",
                    }
                )
            self.toloka.request(
                "POST",
                f"/datasets/{dataset['id']}/items",
                {
                    "fields": [
                        {"name": n, "jsonSchema": {"type": "string"}}
                        for n in ("case_id", "email_text")
                    ],
                    "items": items,
                },
            )
        self.toloka.request(
            "POST",
            f"/pipelines/{review['pipeline_id']}/dataset",
            {"datasetId": review["dataset_id"], "itemLimit": 3},
        )
        self.toloka.request("POST", f"/pipelines/{review['pipeline_id']}/lints", {})
        review["configured"] = True
        storage.put("toloka", review)
        storage.event("Agent prepared the independent audit: " + reason)

    def create_expert_task(self, case_id: str, question: str, reason: str) -> None:
        row = self.emails[case_id]
        answer = storage.get("case:" + case_id)["initial"]
        request = (
            "Scope and quote ONE narrow expert review for a fictional email-security prototype. "
            "Assess the conflicting textual indicators and recommend the exact safe verification step. "
            "Do not investigate whether .example organizations exist: all names/domains are fictional. "
            "Do not authenticate a sender, click links, contact anyone, or request credentials. "
            "No files will be uploaded; all evidence is below. Deliver a short markdown report: "
            "assessment, evidence, limitations, and next step. If a business fact cannot be determined, "
            "say unresolved. A human security reviewer should supply the judgment. "
            "Keep the scope small; request explicit approval of the quote before starting the review. "
            "The maximum available operating budget is USD 45; do not expand scope to use it.\n\n"
            + json.dumps(
                {
                    "email_untrusted": row,
                    "ai_assessment": answer,
                    "expert_question": question,
                    "routing_reason": reason,
                },
                ensure_ascii=False,
            )
        )
        task = {
            "case_id": case_id,
            "status": "submitting",
            "request": request,
            "question": question,
            "routing_reason": reason,
            "conversation_id": "signal-" + fingerprint(self.setup)[:16],
        }
        storage.put("tendem", task)
        result = self.tendem.call(
            "create_task",
            {
                "name": "Signal: expert review " + case_id,
                "description": request,
                "conversation_id": task["conversation_id"],
            },
        )
        task.update(
            {
                "task_id": result["task_id"],
                "status": "scoping",
                "snapshot": result,
                "last_seen_offset": result["last_seen_offset"],
                "next_poll": time.time() + 30,
            }
        )
        storage.put("tendem", task)
        storage.event(
            "Tendem task created; agent is waiting for scope and quote.", case_id
        )

    def approve_toloka(self, payload: dict) -> None:
        review = storage.get("toloka")
        if (
            review["status"] != "awaiting_approval"
            or payload.get("token") != review["approval_token"]
        ):
            raise ValueError("This Toloka approval is stale")
        self.toloka.validate(self.setup["pipeline_id"])
        estimate = self.toloka.estimate(self.setup["pipeline_id"])
        prior = review["estimate"]
        if (
            estimate["graphVersion"] != prior["graphVersion"]
            or estimate["dataset"] != prior["dataset"]
            or estimate["total"] != prior["total"]
        ):
            review.update(estimate=estimate, approval_token=fingerprint(estimate))
            storage.put("toloka", review)
            raise ValueError(
                "Toloka scope or forecast changed. Review the updated quote and approve again."
            )
        storage.reserve(
            "toloka:" + self.setup["pipeline_id"],
            "Toloka",
            usd_cents(estimate["total"]["worstCase"]),
        )
        review["status"] = "submitting"
        storage.put("toloka", review)
        run = self.toloka.start(self.setup["pipeline_id"])
        review.update(status="running", run_id=run["id"], approved_at=storage.now())
        storage.put("toloka", review)
        storage.event("Approved Toloka run started; results will return automatically.")

    def poll_toloka(self) -> None:
        review = storage.get("toloka", {})
        if review.get("status") == "preparing" and review.get("configured"):
            self.toloka.validate(review["pipeline_id"])
            estimate = self.toloka.estimate(review["pipeline_id"])
            if estimate["dataset"]["itemCount"] != len(review["sample_ids"]):
                raise ValueError(
                    "Toloka sample size does not match the agent selection"
                )
            review.update(
                status="awaiting_approval",
                estimate=estimate,
                approval_token=fingerprint(estimate),
            )
            storage.put("toloka", review)
            storage.event("Independent audit forecast ready for approval.")
        if review.get("status") == "running":
            run = self.toloka.run(review["run_id"])
            review["provider_status"] = run["status"]
            review["progress"] = run["result"]
            if run["status"] == "failed":
                review.update(status="failed", error=run["error"])
            elif run["status"] == "succeeded":
                review["status"] = "exporting"
                # Persist before requesting an export, as for other remote mutations.
                storage.put("toloka", review)
                review["export_id"] = self.toloka.export(review["dataset_id"])["id"]
            storage.put("toloka", review)
        if review.get("status") == "exporting" and review.get("export_id"):
            export = self.toloka.export_status(review["export_id"])
            if export["status"] == "failed":
                review.update(status="failed", error=export["error"])
            elif export["status"] == "succeeded":
                labels = self.toloka.download_labels(
                    export["result"]["downloadUrl"], review["sample_ids"]
                )
                for row in labels:
                    cid = row["case_id"]
                    case = storage.get("case:" + cid)
                    case["human_evaluation"] = row
                    case["disagreement"] = row["label"] != case["initial"]["label"]
                    storage.put("case:" + cid, case)
                    storage.event(
                        "Toloka human judgment received"
                        + (
                            " — differs from AI."
                            if case["disagreement"]
                            else " — agrees with AI."
                        ),
                        cid,
                    )
                review.update(
                    status="completed", labels=labels, completed_at=storage.now()
                )
            storage.put("toloka", review)

    def poll_tendem(self) -> None:
        task = storage.get("tendem", {})
        if task.get("status") == "completed":
            if not storage.get("case:" + task["case_id"], {}).get("final"):
                storage.enqueue(
                    "reassess:" + task["task_id"],
                    "reassess",
                    {"case_id": task["case_id"]},
                )
            return
        if (
            not task.get("task_id")
            or task.get("status") in ("completed", "failed")
            or time.time() < task.get("next_poll", 0)
        ):
            return
        snapshot = self.tendem.call("get_task", {"task_id": task["task_id"]})
        task["snapshot"] = snapshot
        task["next_poll"] = time.time() + max(
            30, snapshot.get("poll_after_seconds") or 30
        )
        action = snapshot["next_action"]
        if snapshot.get("latest_chat_offset", 0) > task.get("last_seen_offset", 0):
            chat = self.tendem.call(
                "read_chat", {"task_id": task["task_id"], "from_offset": 0}
            )
            task["chat"] = chat
            task["last_seen_offset"] = chat["last_seen_offset"]
        if action == "await_user_approval":
            contract = self.tendem.call("get_contract", {"task_id": task["task_id"]})
            if snapshot["ready_for_approval"] and contract["state"] == "available":
                if snapshot["price"] != contract["price"]:
                    raise ValueError(
                        "Tendem quote is changing; waiting for a consistent contract"
                    )
                task.update(
                    status="awaiting_approval",
                    contract=contract,
                    approval_token=fingerprint(contract),
                )
        elif action == "await_input":
            task["status"] = "needs_clarification"
            offset = task.get("last_seen_offset", 0)
            if (
                task.get("clarified_offset") != offset
                and task.get("auto_replies", 0) < 2
            ):
                from phishguard.agent import InvestigationAgent

                answer = InvestigationAgent(self).clarify(task)
                task["clarified_offset"] = offset
                task["clarification_reason"] = answer["reason"]
                storage.put("tendem", task)
                if not answer["needs_operator"] and answer["answer"].strip():
                    # Persist the attempted offset before sending; no duplicate automatic replies.
                    task["auto_replies"] = task.get("auto_replies", 0) + 1
                    storage.put("tendem", task)
                    response = self.tendem.call(
                        "send_message",
                        {
                            "task_id": task["task_id"],
                            "text": answer["answer"],
                            "last_seen_offset": offset,
                        },
                    )
                    task.update(
                        status="scoping", last_seen_offset=response["last_seen_offset"]
                    )
                    storage.event(
                        "Agent answered a routine scoping question from existing evidence.",
                        task["case_id"],
                    )
        elif action == "await_user_topup":
            task["status"] = "needs_funding"
        elif action == "fetch_result" or snapshot["status"] == "CLOSED":
            result = self.tendem.call("get_task_result", {"task_id": task["task_id"]})
            if result.get("content"):
                task.update(
                    status="completed", result=result, completed_at=storage.now()
                )
                storage.put("tendem", task)
                storage.enqueue(
                    "reassess:" + task["task_id"],
                    "reassess",
                    {"case_id": task["case_id"]},
                )
                storage.event(
                    "Expert report retrieved; integrating findings with the AI assessment.",
                    task["case_id"],
                )
        elif action == "done":
            task.update(
                status="failed",
                error="Task closed without a fetched report; inspect its provider history.",
            )
        elif action in ("awaiting_tendem_work", "resolve_race"):
            task["status"] = "working" if task.get("approved_at") else "scoping"
        storage.put("tendem", task)

    def approve_tendem(self, payload: dict) -> None:
        task = storage.get("tendem")
        if (
            task["status"] != "awaiting_approval"
            or payload.get("token") != task["approval_token"]
        ):
            raise ValueError("This Tendem approval is stale")
        snapshot = self.tendem.call("get_task", {"task_id": task["task_id"]})
        contract = self.tendem.call("get_contract", {"task_id": task["task_id"]})
        if (
            not snapshot["ready_for_approval"]
            or fingerprint(contract) != task["approval_token"]
            or snapshot["price"] != contract["price"]
        ):
            raise ValueError(
                "Tendem scope or price changed. Wait for the updated quote before approving."
            )
        cents = price_cents(contract["price"])
        balance = self.tendem.call("get_account")["balance"]
        if (
            balance["currency"] != "USD"
            or Decimal(str(balance["amount"])) * 100 < cents
        ):
            raise ValueError("Insufficient Tendem balance; no approval submitted")
        storage.reserve("tendem:" + task["task_id"], "Tendem", cents)
        task["status"] = "approving"
        storage.put("tendem", task)
        result = self.tendem.call(
            "approve_task",
            {
                "task_id": task["task_id"],
                "name": snapshot["name"],
                "price": snapshot["price"]["formatted"],
            },
        )
        task["approval_result"] = result
        if result["approved"]:
            task.update(
                status="working",
                approved_at=storage.now(),
                next_poll=time.time() + max(30, result.get("poll_after_seconds") or 30),
            )
        else:
            task["status"] = "needs_funding"
        storage.put("tendem", task)
        storage.event("Tendem approval response: " + task["status"], task["case_id"])

    def reply(self, payload: dict) -> None:
        task = storage.get("tendem")
        if task["status"] != "needs_clarification":
            raise ValueError("Tendem is not waiting for clarification")
        text = payload.get("text", "").strip()
        if not text or len(text) > 4000:
            raise ValueError("Provide a clarification of 1–4000 characters")
        result = self.tendem.call(
            "send_message",
            {
                "task_id": task["task_id"],
                "text": text,
                "last_seen_offset": task["last_seen_offset"],
            },
        )
        task.update(
            status="scoping",
            last_seen_offset=result["last_seen_offset"],
            next_poll=time.time() + 30,
        )
        storage.put("tendem", task)
        storage.event("Operator clarification sent to Tendem.", task["case_id"])

    def reassess(self, payload: dict) -> None:
        task = storage.get("tendem")
        cid = payload["case_id"]
        case = storage.get("case:" + cid)
        if case.get("final"):
            return
        case["expert_report"] = task["result"]["content"]
        case["final"] = self.analyze(cid, case["expert_report"])
        storage.put("case:" + cid, case)
        storage.event(
            "Assessment updated with expert evidence; original retained. Further escalation requires operator approval.",
            cid,
        )
