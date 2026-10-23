"""Deterministic fake LLM for agent tests (partial STRUCTURE ST05.3).

``FakeLLM`` acts as a structured runnable: each ``ainvoke`` returns the next
scripted item, or raises it if it is an ``Exception``. It records every message
list it receives so tests can assert on retry prompts and prompt-injection
defence (AG01.3). It never touches the network.
"""

from __future__ import annotations

from typing import Any


class FakeLLM:
    def __init__(self, script: list[Any]):
        self.script = list(script)
        self.calls: list[list[Any]] = []  # message lists received, in order
        self._i = 0

    def with_structured_output(self, schema: Any, method: str | None = None) -> "FakeLLM":
        # Already "structured": return self so make_llm-style chaining works.
        self._schema = schema
        self._method = method
        return self

    async def ainvoke(self, messages: list[Any]) -> Any:
        self.calls.append(list(messages))
        if self._i >= len(self.script):
            raise AssertionError("FakeLLM script exhausted — unexpected extra call")
        item = self.script[self._i]
        self._i += 1
        if isinstance(item, Exception):
            raise item
        return item


class PickFirstLLM:
    """Deterministic stand-in for the model in graph tests.

    It answers whichever question the guarded payload asks:

    * an *investigation* payload (it has ``valid_next_steps``): choose the first valid step,
      citing the first evidence ID;
    * an *explanation* payload: three short claims (what / impact / exploit), each citing the
      first evidence ID.

    It records every payload it was shown so tests can assert what the model could and could
    not see.
    """

    def __init__(self):
        self.calls: list[list[Any]] = []
        self.payloads: list[dict] = []

    def with_structured_output(self, schema: Any, method: str | None = None) -> "PickFirstLLM":
        return self

    async def ainvoke(self, messages: list[Any]) -> Any:
        import json

        from aegis.agent.schemas import Claim, Explanation, FixDraft, NextStepDecision, Target

        self.calls.append(list(messages))
        payload = json.loads(messages[1].content)
        self.payloads.append(payload)
        cite = payload["evidence_ids"][:1]
        if "handler_source" in payload:  # a remediation question: this stand-in has no fix to offer
            return FixDraft(finding_id=payload["finding_id"], unified_diff="", evidence_ids=[])
        if "valid_next_steps" in payload:
            return NextStepDecision(
                finding_id=payload["finding_id"],
                next_step=payload["valid_next_steps"][0],
                target=Target(),
                reason_evidence_ids=cite,
            )
        kind = payload["type"].replace("_", " ")
        return Explanation(
            finding_id=payload["finding_id"],
            claims=[
                Claim(field="what", text=f"This is a {kind} issue.", evidence_ids=cite),
                Claim(field="impact", text="It can expose or alter data the application should protect.", evidence_ids=cite),
                Claim(field="exploit", text="The cited evidence shows how the weakness is reached.", evidence_ids=cite),
            ],
        )

    # convenience for tests
    def investigation_payloads(self) -> list[dict]:
        return [p for p in self.payloads if "valid_next_steps" in p]

    def explanation_payloads(self) -> list[dict]:
        return [p for p in self.payloads if "valid_next_steps" not in p]
