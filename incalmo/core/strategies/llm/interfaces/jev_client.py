"""Thin client for TypeSafe AI's Jev "System One" model.

Jev is not a text-generating LLM: it takes structured program state plus a set
of pre-declared questions and returns a *choice* from the allowed options for
each, with calibrated probabilities (see the "choice" primitive at
https://docs.typesafe.ai/primitives/choice). That is exactly the shape Incalmo's
high-level action space needs — a fixed menu of "which action, with which
parameters" — so the Jev interface (jev_interface.py) drives the attack by
asking Jev a *series* of choice questions instead of parsing free-text tags.

This module isolates the one integration seam: given a `state` string and a
single choice question (`instructions` + `criteria` mapping option-key ->
description), return the selected option key, its confidence, and the per-option
probabilities. It prefers the official `typesafe_sdk` when installed and falls
back to a direct REST call so a run does not hard-depend on the SDK being present
in the attacker image.

Credential handling matches the named-deployment registry: the key is read from
a named environment variable (never hard-coded), resolved fail-fast at call time.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


# Endpoint from the Jev choice-primitive docs; overridable for a proxy / mock.
_DEFAULT_BASE_URL = "https://api.typesafe.ai/v1/systemone"


@dataclass
class JevChoiceResult:
    """One resolved choice question."""

    choice: str
    confidence: float | None = None
    probabilities: Dict[str, float] = field(default_factory=dict)
    input_tokens: int = 0
    output_tokens: int = 0
    raw: Any = None


class JevClient:
    """Poses single-question 'choice' requests to Jev and returns the selection.

    `model` is the Jev model id (e.g. "jev-latest"). `api_key_env` names the
    environment variable holding the key; it is resolved on first use and a
    missing key is a fail-fast error, never a silent unauthenticated call.
    """

    def __init__(
        self,
        model: str = "jev-latest",
        api_key_env: str = "TYPESAFE_API_KEY",
        base_url: Optional[str] = None,
        logger=None,
    ):
        self.model = model
        self.api_key_env = api_key_env
        self.base_url = base_url or os.environ.get(
            "TYPESAFE_BASE_URL", _DEFAULT_BASE_URL
        )
        self.logger = logger
        self._sdk_client = None
        self._sdk_choice = None
        self._tried_sdk = False

    # ── credential ────────────────────────────────────────────────────────────
    def _api_key(self) -> str:
        key = os.environ.get(self.api_key_env)
        if not key:
            raise RuntimeError(
                f"Jev deployment requires credential '{self.api_key_env}', "
                f"but that environment variable is unset."
            )
        return key

    # ── SDK path ──────────────────────────────────────────────────────────────
    def _ensure_sdk(self) -> bool:
        """Lazily import and construct the typesafe_sdk client. Returns True if
        the SDK is usable, False if it is not installed (caller falls back to
        REST). Import is lazy so the SDK is not a hard dependency of the repo."""
        if self._tried_sdk:
            return self._sdk_client is not None
        self._tried_sdk = True
        try:
            from typesafe_sdk import Choice, TypeSafeClient  # type: ignore
        except Exception as e:  # pragma: no cover - depends on env
            if self.logger:
                self.logger.info(
                    f"[Jev] typesafe_sdk not available ({e}); using REST fallback."
                )
            return False
        # The SDK reads TYPESAFE_API_KEY itself, but resolve fail-fast here too so
        # a missing key is reported the same way on both paths.
        self._api_key()
        self._sdk_client = TypeSafeClient()
        self._sdk_choice = Choice
        return True

    def _ask_via_sdk(
        self, state: str, question_id: str, instructions: str, criteria: Dict[str, str]
    ) -> JevChoiceResult:
        Choice = self._sdk_choice
        response = self._sdk_client.system_one(
            state=state,
            model=self.model,
            questions={
                question_id: Choice(instructions=instructions, criteria=criteria)
            },
        )
        ans = response.answers[question_id]
        usage = getattr(response, "usage", None)
        return JevChoiceResult(
            choice=getattr(ans, "choice"),
            confidence=getattr(ans, "confidence", None),
            probabilities=dict(getattr(ans, "probabilities", {}) or {}),
            input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
            output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
            raw=response,
        )

    # ── REST path ─────────────────────────────────────────────────────────────
    def _ask_via_rest(
        self, state: str, question_id: str, instructions: str, criteria: Dict[str, str]
    ) -> JevChoiceResult:
        import httpx  # already a dependency (see langchain_registry)

        body = {
            "state": state,
            "model": self.model,
            "questions": {
                question_id: {
                    "type": "choice",
                    "instructions": instructions,
                    "criteria": criteria,
                }
            },
        }
        headers = {
            "Authorization": f"Bearer {self._api_key()}",
            "Content-Type": "application/json",
        }
        resp = httpx.post(self.base_url, headers=headers, json=body, timeout=120.0)
        resp.raise_for_status()
        data = resp.json()
        ans = (data.get("answers") or {}).get(question_id) or {}
        usage = data.get("usage") or {}
        choice = ans.get("choice")
        if choice is None:
            raise RuntimeError(
                f"Jev response had no choice for question '{question_id}': "
                f"{json.dumps(data)[:500]}"
            )
        return JevChoiceResult(
            choice=choice,
            confidence=ans.get("confidence"),
            probabilities=dict(ans.get("probabilities") or {}),
            input_tokens=int(usage.get("input_tokens", 0) or 0),
            output_tokens=int(usage.get("output_tokens", 0) or 0),
            raw=data,
        )

    # ── public ────────────────────────────────────────────────────────────────
    def ask_choice(
        self,
        state: str,
        question_id: str,
        instructions: str,
        criteria: Dict[str, str],
    ) -> JevChoiceResult:
        """Pose one choice question and return Jev's selection.

        `criteria` maps each allowed option key to a human description; Jev
        returns exactly one of those keys. If Jev returns a key outside the menu
        (should not happen), the caller is responsible for validating it.
        """
        if not criteria:
            raise ValueError("ask_choice requires at least one option in criteria")
        if self._ensure_sdk():
            return self._ask_via_sdk(state, question_id, instructions, criteria)
        return self._ask_via_rest(state, question_id, instructions, criteria)
