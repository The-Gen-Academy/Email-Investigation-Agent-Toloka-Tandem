import json

import httpx
import pytest

from phishguard.core import Email
from phishguard.investigator import investigate


def fake_client(data):
    def handler(request):
        assert request.url.path.endswith("/chat/completions")
        messages = json.loads(request.content)["messages"]
        assert "untrusted" in messages[0]["content"].lower()
        return httpx.Response(
            200, json={"choices": [{"message": {"content": json.dumps(data)}}]}
        )

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_llm_is_primary_decision():
    email = Email("news@example.com", "Newsletter", "This is a normal newsletter")
    with fake_client(
        {
            "label": "suspicious",
            "confidence": 0.95,
            "reasons": ["Impersonation indicated by wording"],
            "explanation": "Potential impersonation",
        }
    ) as client:
        result = investigate(
            email,
            api_key="test",
            base_url="https://mock.test/v1",
            model="test-model",
            client=client,
        )
    assert result.label == "suspicious" and result.source == "live_llm"
    assert not result.needs_expert


def test_deterministic_policy_overrides_routing_not_llm_verdict():
    email = Email("team@example.com", "Status", "See http://192.0.2.10/info")
    with fake_client(
        {
            "label": "no_obvious_indicators",
            "confidence": 0.93,
            "reasons": ["Neutral wording"],
            "explanation": "No obvious signals",
        }
    ) as client:
        result = investigate(
            email,
            api_key="test",
            base_url="https://mock.test/v1",
            model="test-model",
            client=client,
        )
    assert result.label == "no_obvious_indicators"
    assert result.needs_expert
    assert any("Routing:" in reason for reason in result.reasons)


def test_invalid_json_fails_closed():
    with fake_client(
        {"label": "safe", "confidence": 0.95, "reasons": ["x"], "explanation": "x"}
    ) as client:
        with pytest.raises(ValueError):
            investigate(
                Email("a@b", "x", "y"),
                api_key="test",
                base_url="https://mock.test/v1",
                model="test-model",
                client=client,
            )


def test_missing_key_does_not_use_rules():
    with pytest.raises(ValueError, match="LLM_API_KEY"):
        investigate(
            Email("a@b", "test", "test"),
            api_key="",
            base_url="https://mock.test/v1",
            model="test-model",
        )
