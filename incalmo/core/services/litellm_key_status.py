"""Best-effort tracking of the shared LITELLM_API_KEY's spend/budget.

The virtual key Incalmo authenticates to the CMU LiteLLM gateway with is
restricted to `llm_api_routes` - it can't call the admin `/key/info` endpoint to
look up its own spend on demand (confirmed live: the gateway returns "Virtual key
is not allowed to call this route"). But every actual chat completion through it
already returns the running totals as response headers (`x-litellm-key-spend`,
`x-litellm-key-max-budget`) - see langchain_registry._HeaderCapturingHTTPClient.

This module persists the most recently observed pair to a small shared file (not
tied to any one trial/operation_id, since it's about the credential, not a run),
so the dashboard's usage tab has something to show even without an admin key. If
an admin key IS configured (LITELLM_ADMIN_KEY), incalmo/c2server/routes/
usage_routes.py queries /key/info directly instead and this file is unused for
display - but is still written on every call, as a free fallback if the admin key
is ever removed or starts erroring.
"""

import json
import os
import time
from pathlib import Path

_STATUS_PATH = Path(
    os.environ.get("INCALMO_OUTPUT_DIR", "output")
) / "_litellm_key_status.json"


def record_key_status(headers: dict) -> None:
    """Persist x-litellm-key-spend/-max-budget from a response's headers, if
    present. No-ops silently if the headers don't carry them (e.g. a non-
    litellm_proxy call, or an older gateway version without these headers) -
    never raises, since this is best-effort telemetry, not load-bearing.
    """
    spend = headers.get("x-litellm-key-spend")
    max_budget = headers.get("x-litellm-key-max-budget")
    if spend is None and max_budget is None:
        return
    try:
        _STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
        _STATUS_PATH.write_text(
            json.dumps(
                {
                    "spend": float(spend) if spend is not None else None,
                    "max_budget": float(max_budget) if max_budget is not None else None,
                    "as_of": time.time(),
                }
            )
        )
    except (OSError, TypeError, ValueError):
        pass


def read_key_status() -> dict | None:
    """The most recently persisted {spend, max_budget, as_of} dict, or None if
    no litellm_proxy call has ever been observed on this machine."""
    if not _STATUS_PATH.exists():
        return None
    try:
        return json.loads(_STATUS_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return None
