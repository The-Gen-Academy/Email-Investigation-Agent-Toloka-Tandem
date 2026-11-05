import json
from types import SimpleNamespace

import httpx
import pytest

from phishguard import storage
from phishguard.agent import InvestigationAgent
from phishguard.toloka import TolokaClient, usd_cents
from phishguard.workflow import price_cents


@pytest.fixture(autouse=True)
def isolated_database(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DATABASE", tmp_path / "signal.db")
    storage.initialize()


def test_saved_evidence_survives_new_connections():
    storage.put("case:one", {"initial": {"label": "uncertain"}})
    assert storage.get("case:one")["initial"]["label"] == "uncertain"


def test_duplicate_button_clicks_enqueue_once():
    storage.enqueue("approve:one", "approve_toloka", {"token": "one"})
    storage.enqueue("approve:one", "approve_toloka", {"token": "one"})
    assert storage.claim()["id"] == "approve:one"
    assert storage.claim() is None


def test_interrupted_job_is_not_replayed():
    storage.enqueue("approve:one", "approve_toloka")
    storage.claim()
    storage.recover()
    assert storage.claim() is None
    assert storage.commands()[0]["status"] == "error"


def test_budget_reservations_accumulate_across_jobs():
    storage.reserve("one", "Toloka", 2500)
    with pytest.raises(ValueError, match="operating limit"):
        storage.reserve("two", "Toloka", 2001)
    assert storage.committed("Toloka") == 2500
    assert storage.committed("Tendem") == 0


def test_repeated_approval_is_blocked():
    storage.reserve("one", "Tendem", 300)
    with pytest.raises(ValueError, match="already"):
        storage.reserve("one", "Tendem", 300)


@pytest.mark.parametrize("price", ["$NaN", "-$2.00", "EUR 2.00", "$2.001"])
def test_bad_toloka_quote_fails_closed(price):
    with pytest.raises(ValueError):
        usd_cents(price)


def test_forecast_uses_integer_cents():
    assert usd_cents("$2.59") == 259
    assert price_cents({"amount": 2.59, "currency": "USD"}) == 259


@pytest.mark.parametrize(
    "amount,currency", [(float("nan"), "USD"), (-1, "USD"), (2, "EUR")]
)
def test_bad_tendem_quote_fails_closed(amount, currency):
    with pytest.raises(ValueError):
        price_cents({"amount": amount, "currency": currency})


def test_agent_cannot_finish_before_assessing_cases():
    agent = InvestigationAgent(SimpleNamespace(config={}, emails={"case01": {}}))
    assert "error" in agent.dispatch("finish", {"summary": "done"})
    assert storage.get("batch") is None


def test_agent_reuses_saved_assessments():
    storage.put("case:case01", {"initial": {"label": "suspicious"}})
    agent = InvestigationAgent(SimpleNamespace(config={}, emails={"case01": {}}))
    assert (
        agent.dispatch("investigate_email", {"case_id": "case01"})["label"]
        == "suspicious"
    )


def test_agent_rejects_audit_that_omits_available_category():
    for cid, label in [
        ("one", "suspicious"),
        ("two", "no_obvious_indicators"),
        ("three", "no_obvious_indicators"),
        ("four", "uncertain"),
    ]:
        storage.put("case:" + cid, {"initial": {"label": label}})
    agent = InvestigationAgent(
        SimpleNamespace(
            config={}, emails={cid: {} for cid in ["one", "two", "three", "four"]}
        )
    )
    result = agent.dispatch(
        "prepare_quality_audit",
        {"case_ids": ["one", "two", "three"], "reason": "sample"},
    )
    assert "error" in result


def test_agent_never_submits_second_expert_task():
    storage.put("tendem", {"case_id": "case01", "status": "submitting"})
    agent = InvestigationAgent(SimpleNamespace(config={}, emails={"case01": {}}))
    result = agent.dispatch(
        "request_expert_review",
        {
            "case_id": "case01",
            "question": "Clarify conflict",
            "reason": "Conflicting signals",
        },
    )
    assert result["status"] == "already_requested"


def test_export_does_not_fetch_arbitrary_hosts():
    with pytest.raises(ValueError):
        TolokaClient("test").download_labels("https://127.0.0.1/private", ["case01"])


def test_remote_mutation_is_not_retried(monkeypatch):
    calls = []

    def request(self, method, url, **kwargs):
        calls.append(url)
        return httpx.Response(503, text="unavailable")

    monkeypatch.setattr(httpx.Client, "request", request)
    with pytest.raises(RuntimeError):
        TolokaClient("test").start("pipeline")
    assert len(calls) == 1


def test_model_tool_loop_executes_model_selected_tool(monkeypatch):
    storage.put("case:case01", {"initial": {"label": "suspicious"}})
    storage.put("toloka", {"status": "awaiting_approval"})
    agent = InvestigationAgent(
        SimpleNamespace(config={}, emails={"case01": {"subject": "Example"}})
    )
    responses = iter(
        [
            {
                "content": None,
                "tool_calls": [
                    {
                        "id": "a",
                        "type": "function",
                        "function": {
                            "name": "inspect_email",
                            "arguments": json.dumps({"case_id": "case01"}),
                        },
                    }
                ],
            },
            {
                "content": None,
                "tool_calls": [
                    {
                        "id": "b",
                        "type": "function",
                        "function": {
                            "name": "finish",
                            "arguments": json.dumps(
                                {"summary": "Investigation coordinated"}
                            ),
                        },
                    }
                ],
            },
        ]
    )
    monkeypatch.setattr(agent, "completion", lambda *args: next(responses))
    agent.run()
    assert storage.get("batch")["status"] == "assessed"
    assert any("inspect_email" in e["message"] for e in storage.events())


def test_changed_toloka_quote_requires_new_approval():
    from phishguard.workflow import Workflow, fingerprint

    old = {
        "graphVersion": "v1",
        "dataset": {"itemCount": 3},
        "total": {"worstCase": "$2.59"},
    }
    new = old | {"total": {"worstCase": "$3.00"}}
    storage.put(
        "toloka",
        {
            "status": "awaiting_approval",
            "estimate": old,
            "approval_token": fingerprint(old),
        },
    )
    workflow = Workflow.__new__(Workflow)
    workflow.setup = {"pipeline_id": "pipeline"}
    workflow.toloka = SimpleNamespace(validate=lambda _: None, estimate=lambda _: new)
    with pytest.raises(ValueError, match="changed"):
        workflow.approve_toloka({"token": fingerprint(old)})
    assert storage.committed("Toloka") == 0
    assert storage.get("toloka")["approval_token"] == fingerprint(new)


def test_tendem_contract_change_never_calls_approve():
    from phishguard.workflow import Workflow, fingerprint

    old = {
        "task_id": "task",
        "state": "available",
        "contract": {"scope": "one case"},
        "price": {"amount": 7.03, "currency": "USD", "formatted": "$7.03"},
    }
    new = old | {"contract": {"scope": "expanded work"}}
    storage.put(
        "tendem",
        {
            "status": "awaiting_approval",
            "task_id": "task",
            "contract": old,
            "approval_token": fingerprint(old),
        },
    )
    calls = []

    def call(name, arguments=None):
        calls.append(name)
        return (
            {"ready_for_approval": True, "price": old["price"]}
            if name == "get_task"
            else new
        )

    workflow = Workflow.__new__(Workflow)
    workflow.tendem = SimpleNamespace(call=call)
    with pytest.raises(ValueError, match="changed"):
        workflow.approve_tendem({"token": fingerprint(old)})
    assert "approve_task" not in calls
    assert storage.committed("Tendem") == 0


def test_completed_tendem_report_reassesses_without_resubmitting():
    from phishguard.workflow import Workflow

    storage.put(
        "tendem", {"status": "completed", "result": {"content": "Independent findings"}}
    )
    storage.put("case:one", {"initial": {"label": "uncertain"}})
    workflow = Workflow.__new__(Workflow)
    workflow.analyze = lambda cid, evidence: {
        "label": "suspicious",
        "evidence": evidence,
    }
    workflow.reassess({"case_id": "one"})
    case = storage.get("case:one")
    assert case["initial"]["label"] == "uncertain"
    assert case["final"]["label"] == "suspicious"
    assert case["expert_report"] == "Independent findings"
