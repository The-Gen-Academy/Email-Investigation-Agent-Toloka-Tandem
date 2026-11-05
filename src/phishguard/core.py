"""Small shared types. Decisions come from the LLM, not these dataclasses."""

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Email:
    sender: str
    subject: str
    body: str


@dataclass(frozen=True)
class Assessment:
    label: str
    reasons: list[str]
    needs_expert: bool
    explanation: str
    source: str = "live_llm"
    confidence: float | None = None

    def as_dict(self) -> dict:
        return asdict(self)
