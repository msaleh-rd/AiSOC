"""Proves customer PII never reaches an outbound LLM call (no-exfiltration claim).

``docs/audit/REALITY_REPORT.md`` flagged this as an OVERCLAIM: the reversible
:class:`app.privacy.redactor.Pseudonymizer` (Phase 1.4) existed and was unit
tested in isolation (``test_privacy_redactor.py``), but was never actually
wired into the two real outbound LLM call sites:

* ``app.api.explain._llm_summary`` — the on-demand alert explainer.
* ``app.agents.auto_triage_agent.run_auto_triage`` — the always-on,
  highest-volume path (every fused alert gets auto-triaged).

These tests capture the exact outbound payload each path sends to the model
and assert planted internal PII (an internal IP, an email, a Windows path,
and a down-level domain\\user) is never present verbatim — only opaque
tokens (``IP_1``, ``EMAIL_1``, ``PATH_1``, ``USER_1``) may appear. They also
assert the analyst-facing result (the explain summary / the stored
rationale) is rehydrated back to the real values, since redaction must be
invisible to the human on the other end.
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Any

import httpx
import pytest

os.environ.setdefault("AISOC_AIRGAPPED", "false")

# Planted PII — none of these literal strings may appear in the captured
# outbound request body.
_INTERNAL_IP = "10.20.30.40"
_EMAIL = "victim.analyst@customer-corp.example"
_WIN_PATH = r"C:\Users\victim.analyst\secrets.txt"
_DOMAIN_USER = r"CORP\victim.analyst"


class _FakeResponse:
    def __init__(self, content: str) -> None:
        self._content = content

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return {"choices": [{"message": {"content": self._content}}]}


def _install_fake_async_client(monkeypatch: pytest.MonkeyPatch, captured: dict[str, Any], llm_reply: str) -> None:
    """Patch the real ``httpx.AsyncClient`` so ``explain.py``'s function-local
    ``import httpx`` (it imports lazily, not at module scope) picks up the
    fake — patching an attribute on ``app.api.explain`` itself would not be
    seen by that local import."""

    class _FakeAsyncClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            captured["init_kwargs"] = kwargs

        async def __aenter__(self) -> "_FakeAsyncClient":
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def post(self, url: str, *, headers: dict[str, str] | None = None, json: dict[str, Any] | None = None) -> _FakeResponse:  # noqa: A002
            captured["url"] = url
            captured["headers"] = headers
            captured["json"] = json
            return _FakeResponse(llm_reply)

    monkeypatch.setattr(httpx, "AsyncClient", _FakeAsyncClient)


# ---------------------------------------------------------------------------
# app.api.explain._llm_summary
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_explain_llm_summary_redacts_pii_before_egress(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.api import explain as explain_mod
    from app.security.llm_resolver import LlmConfig

    captured: dict[str, Any] = {}
    # The fake model "reasons" over the token it received and echoes a fixed
    # phrase back — a real model cannot invent PII it never saw.
    _install_fake_async_client(monkeypatch, captured, "The activity appears to be a routine login.")

    alert = {
        "title": "Suspicious login",
        "severity": "high",
        "source": "okta",
        "description": (
            f"User {_EMAIL} logged in from internal host {_INTERNAL_IP}, "
            f"then exfiltrated {_WIN_PATH} while authenticated as {_DOMAIN_USER}."
        ),
        "tags": ["ato"],
    }
    llm_config = LlmConfig(
        allowed=True,
        base_url="https://api.example.com/v1",
        model="test-model",
        api_key="test-key",
        source="environment",
        reason="",
    )

    await explain_mod._llm_summary(alert, [], "fallback summary", llm_config, tenant_id="tenant-a")

    assert captured, "expected the fake httpx client to have been called"
    sent_body = json.dumps(captured["json"])
    assert _INTERNAL_IP not in sent_body
    assert _EMAIL not in sent_body
    assert _WIN_PATH not in sent_body
    assert _DOMAIN_USER not in sent_body
    # A token of the expected shape must have replaced each PII category.
    assert "IP_" in sent_body
    assert "EMAIL_" in sent_body
    assert "PATH_" in sent_body
    assert "USER_" in sent_body


@pytest.mark.asyncio
async def test_explain_llm_summary_rehydrates_response_for_analyst(monkeypatch: pytest.MonkeyPatch) -> None:
    """The LLM only ever sees tokens; whatever it echoes back must be
    rehydrated to the real value before the analyst sees it."""
    from app.api import explain as explain_mod
    from app.security.llm_resolver import LlmConfig

    captured: dict[str, Any] = {}
    # The fake model echoes the token it was given (EMAIL_1) back in its
    # answer, exactly as a real LLM would since it never saw the real email.
    _install_fake_async_client(monkeypatch, captured, "Contacted EMAIL_1 about the login.")

    alert = {
        "title": "Suspicious login",
        "severity": "high",
        "source": "okta",
        "description": f"User {_EMAIL} logged in.",
        "tags": [],
    }
    llm_config = LlmConfig(
        allowed=True,
        base_url="https://api.example.com/v1",
        model="test-model",
        api_key="test-key",
        source="environment",
        reason="",
    )

    result = await explain_mod._llm_summary(alert, [], "fallback", llm_config, tenant_id="tenant-a")

    assert _EMAIL in result
    assert "EMAIL_1" not in result


# ---------------------------------------------------------------------------
# app.agents.auto_triage_agent.run_auto_triage
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_auto_triage_redacts_pii_before_egress(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.agents import auto_triage_agent as ata
    from app.models.state import InvestigationState

    captured: dict[str, Any] = {}

    class _FakeLLMResponse:
        content = json.dumps(
            {
                "verdict": "true_positive",
                "confidence": 0.9,
                "rationale": f"Correlates with {_DOMAIN_USER} on the flagged host.",
            }
        )

    async def _fake_safe_ainvoke(llm: Any, messages: list[Any]) -> _FakeLLMResponse:
        # Capture exactly what was about to be sent to the model.
        captured["messages"] = [getattr(m, "content", "") for m in messages]
        return _FakeLLMResponse()

    monkeypatch.setattr(ata, "safe_ainvoke", _fake_safe_ainvoke)
    monkeypatch.setattr(ata, "make_chat_model", lambda *a, **k: object())

    state = InvestigationState(
        run_id=uuid.uuid4(),
        incident_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        alert_summary=f"Login from {_INTERNAL_IP} as {_DOMAIN_USER}",
        raw_alert={
            "severity": "high",
            "risk_score": 0.9,
            "src_ip": _INTERNAL_IP,
            "hostname": "internal-host.local",
            "notes": f"Exfil path: {_WIN_PATH}; contact {_EMAIL}",
        },
    )

    result_state = await ata.run_auto_triage(state)

    sent_text = "\n".join(captured["messages"])
    assert _INTERNAL_IP not in sent_text
    assert _EMAIL not in sent_text
    assert _WIN_PATH not in sent_text
    assert _DOMAIN_USER not in sent_text
    assert "IP_" in sent_text
    assert "PATH_" in sent_text

    # The rationale stored for the analyst (confidence_basis) must be
    # rehydrated back to the real username, not the opaque token.
    basis_text = "\n".join(result_state.confidence_basis)
    assert _DOMAIN_USER in basis_text
    assert "USER_" not in basis_text
