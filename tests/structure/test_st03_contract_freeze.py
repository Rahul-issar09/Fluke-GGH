"""ST03.2 — contract snapshot freeze test.

Any change to a frozen contract (evidence.models / agent.schemas / agent.state
/ safety.models / api.schemas) fails this test until the golden snapshot is
regenerated with ``AEGIS_UPDATE_CONTRACTS=1`` — which is the explicit-approval
step required by PHASES rule 4.
"""

from __future__ import annotations

import enum
import json
import os
import pathlib

import pytest

from _contract_registry import CONTRACTS

pytestmark = pytest.mark.phase("ST03")

_GOLDEN_DIR = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "golden" / "contracts"


def _schema_for(obj) -> dict:
    """Deterministic structural snapshot of a frozen object."""
    if isinstance(obj, type) and issubclass(obj, enum.Enum):
        return {"kind": "enum", "members": {m.name: m.value for m in obj}}
    if hasattr(obj, "model_json_schema"):  # pydantic / SQLModel
        return {"kind": "model", "schema": obj.model_json_schema()}
    # TypedDict (AegisState / FixState)
    annotations = getattr(obj, "__annotations__", {})
    required = sorted(getattr(obj, "__required_keys__", set()))
    optional = sorted(getattr(obj, "__optional_keys__", set()))
    return {
        "kind": "typeddict",
        "keys": {name: str(ann) for name, ann in annotations.items()},
        "required": required,
        "optional": optional,
    }


def _snapshot(module: str) -> dict:
    return {obj.__name__: _schema_for(obj) for obj in CONTRACTS[module]}


def _dump(data: dict) -> str:
    return json.dumps(data, indent=2, sort_keys=True)


def _maybe_update() -> None:
    if os.getenv("AEGIS_UPDATE_CONTRACTS") != "1":
        return
    _GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    for module in CONTRACTS:
        (_GOLDEN_DIR / f"{module}.json").write_text(_dump(_snapshot(module)), encoding="utf-8")


_maybe_update()


@pytest.mark.parametrize("module", sorted(CONTRACTS))
def test_contract_matches_golden(module: str):
    golden_file = _GOLDEN_DIR / f"{module}.json"
    assert golden_file.exists(), (
        f"missing golden for {module}; generate once with AEGIS_UPDATE_CONTRACTS=1"
    )
    expected = json.loads(golden_file.read_text(encoding="utf-8"))
    actual = _snapshot(module)
    assert actual == expected, (
        f"frozen contract '{module}' changed. If intended, this needs explicit "
        f"approval (PHASES rule 4): regenerate with AEGIS_UPDATE_CONTRACTS=1."
    )
