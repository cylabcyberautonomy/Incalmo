"""API usage/spend monitoring routes for the C2 server.

Backs the dashboard's live API-usage tab: current OpenRouter credit usage and
current LiteLLM gateway key spend, for the credentials Incalmo is actually
configured with (OPENROUTER_API_KEY / LITELLM_API_KEY).
"""

import os

import requests
from flask import Blueprint, jsonify

from incalmo.core.services.litellm_key_status import read_key_status

usage_bp = Blueprint("usage", __name__)

# /api/v1/key (singular) is OpenRouter's self-serve endpoint: the calling key
# reports its OWN per-key limit/usage, no separate Provisioning key needed. This
# is the per-key spend cap the OpenRouter dashboard's key-edit screen calls
# "Credit limit" - distinct from (and more useful than) /api/v1/credits, which
# is account-wide lifetime purchased-credits/usage, not this key's own cap.
OPENROUTER_KEY_URL = "https://openrouter.ai/api/v1/key"
_REQUEST_TIMEOUT = 10


def _get_openrouter_usage() -> dict:
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        return {"limit": None, "limit_remaining": None, "usage": None, "error": "OPENROUTER_API_KEY not set"}

    try:
        resp = requests.get(
            OPENROUTER_KEY_URL,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=_REQUEST_TIMEOUT,
        )
    except requests.RequestException as e:
        return {"limit": None, "limit_remaining": None, "usage": None, "error": str(e)}

    if resp.status_code != 200:
        return {
            "limit": None,
            "limit_remaining": None,
            "usage": None,
            "error": f"OpenRouter returned {resp.status_code}: {resp.text[:200]}",
        }

    data = resp.json().get("data") or {}
    return {
        # None means "no limit set" (unlimited key) - distinct from 0.
        "limit": data.get("limit"),
        "limit_remaining": data.get("limit_remaining"),
        "usage": data.get("usage"),
        "error": None,
    }


def _proxy_root(base_url: str) -> str:
    # LITELLM_BASE_URL points at the OpenAI-compatible surface (.../v1);
    # admin routes like /key/info live at the proxy root, one level up.
    root = base_url.rstrip("/")
    if root.endswith("/v1"):
        root = root[: -len("/v1")]
    return root


def _query_key_info(auth_key: str, root: str, target_key: str | None = None) -> tuple[dict | None, str | None]:
    """One /key/info call. Returns ({spend, max_budget}, None) on success, or
    (None, error message) on any failure - never raises."""
    try:
        params = {"key": target_key} if target_key else {}
        resp = requests.get(
            f"{root}/key/info",
            headers={"Authorization": f"Bearer {auth_key}"},
            params=params,
            timeout=_REQUEST_TIMEOUT,
        )
    except requests.RequestException as e:
        return None, str(e)

    if resp.status_code != 200:
        return None, f"/key/info returned {resp.status_code}: {resp.text[:200]}"

    data = resp.json()
    # LiteLLM has moved spend/max_budget between the top level and a nested
    # "info" object across versions - check both.
    info = data.get("info") or {}
    return {
        "spend": data.get("spend", info.get("spend")),
        "max_budget": data.get("max_budget", info.get("max_budget")),
    }, None


def _get_litellm_usage() -> dict:
    """Three ways to get LiteLLM spend, tried in order of preference:

    1. Self-serve: LITELLM_API_KEY queries /key/info about itself. Works once
       that key's allowed_routes includes "/key/info" alongside its existing
       llm_api_routes entry - a narrow, read-only grant, no second credential
       needed. Set via (needs a master key to call, once):
           curl '<gateway-root>/key/update' -H 'Authorization: Bearer <master key>' \
             -d '{"key": "<LITELLM_API_KEY>", "allowed_routes": ["llm_api_routes", "/key/info"]}'
    2. A separate LITELLM_ADMIN_KEY, if configured, querying LITELLM_API_KEY's
       info by name - works even if (1) isn't set up.
    3. Best-effort: the x-litellm-key-spend/-max-budget headers from the most
       recent actual call (see litellm_key_status.py) - only as fresh as the
       last call, but needs no extra permission at all.
    """
    base_url = os.environ.get("LITELLM_BASE_URL")
    api_key = os.environ.get("LITELLM_API_KEY")
    admin_key = os.environ.get("LITELLM_ADMIN_KEY")
    root = _proxy_root(base_url) if base_url else None

    last_error = None

    if root and api_key:
        result, err = _query_key_info(api_key, root)
        if result:
            return {**result, "source": "key_info", "as_of": None, "error": None}
        last_error = err

    if root and admin_key and api_key:
        result, err = _query_key_info(admin_key, root, target_key=api_key)
        if result:
            return {**result, "source": "key_info", "as_of": None, "error": None}
        last_error = err

    status = read_key_status()
    if status:
        return dict(status, source="last_call_headers", error=last_error)

    return {
        "spend": None,
        "max_budget": None,
        "source": "unavailable",
        "as_of": None,
        "error": last_error
        or "LITELLM_API_KEY can't self-query /key/info, no LITELLM_ADMIN_KEY configured, "
        "and no litellm_proxy call observed yet",
    }


@usage_bp.route("/get_api_usage", methods=["GET"])
def get_api_usage():
    """Current OpenRouter + LiteLLM spend, for the dashboard's live usage tab."""
    return jsonify(
        {
            "openrouter": _get_openrouter_usage(),
            "litellm": _get_litellm_usage(),
        }
    ), 200
