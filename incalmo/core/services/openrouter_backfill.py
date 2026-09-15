"""Backfill OpenRouter generation-time / native-token stats for a token_usage.json log.

OpenRouter doesn't include `generation_time`, `latency`, or the upstream provider's
own token counts (`native_tokens_prompt`/`native_tokens_completion`) in the chat
completion response itself - they're only available via a follow-up
`GET /api/v1/generation?id=...` call, and that lookup isn't reliably ready
immediately: in testing, a query at t+3s after the original call 404'd, but the
same id succeeded by t+8s. Doing this lookup inline, in the live attacker loop,
would add a second network round-trip (plus retry delay) to every OpenRouter-routed
LLM call in every experiment run - so this runs once, after a trial finishes,
against the token_usage.json log it already wrote (see LLMStrategy.finished_cb,
which calls run_backfill via asyncio.to_thread so it doesn't block the event loop).

Also used directly as a CLI via scripts/backfill_openrouter_generation_stats.py, for
re-running against an older log or one from a run that didn't have the automatic
hook (e.g. before this module existed).

Retention caveat: empirically confirmed OpenRouter keeps generation records
retrievable for at least ~42 minutes (checked against a real id from earlier in a
session); no documented upper bound was found in OpenRouter's docs. That's why this
runs at the end of each individual trial rather than being deferred to the end of
an entire multi-trial experiment corpus, which could span hours.
"""

import json
import os
import sys
import time
from pathlib import Path

import requests

GENERATION_URL = "https://openrouter.ai/api/v1/generation"

DEFAULT_MAX_RETRIES = 5
DEFAULT_RETRY_DELAY = 3.0
DEFAULT_SLEEP_BETWEEN = 0.25


def load_openrouter_response_ids(token_usage_path: Path) -> list[str]:
    """response_id values that are OpenRouter's own ids ("gen-..."), deduped and
    in first-seen order. Other providers' ids (chatcmpl-..., msg_..., etc.) aren't
    queryable against this endpoint and are skipped. Malformed lines are skipped
    rather than aborting the whole backfill over one bad row.
    """
    ids: list[str] = []
    seen: set[str] = set()
    with open(token_usage_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            rid = row.get("response_id")
            if rid and rid.startswith("gen-") and rid not in seen:
                seen.add(rid)
                ids.append(rid)
    return ids


def fetch_generation_stats(
    generation_id: str,
    api_key: str,
    max_retries: int = DEFAULT_MAX_RETRIES,
    retry_delay: float = DEFAULT_RETRY_DELAY,
    log=None,
) -> dict | None:
    """Query OpenRouter's /generation endpoint for one id, retrying on 404 (not
    ready yet) and 429 (rate limited) since both are transient. Returns None
    (never raises) on repeated failure, so one bad id doesn't abort the whole
    backfill. `log`, if given, is a logger (or anything with .warning/.error) used
    instead of stderr - so this reads sensibly inside the attacker-loop's own log
    file, not just when run as a standalone script.
    """

    def warn(msg: str):
        if log is not None:
            log.warning(msg)
        else:
            print(msg, file=sys.stderr)

    headers = {"Authorization": f"Bearer {api_key}"}
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.get(
                GENERATION_URL,
                headers=headers,
                params={"id": generation_id},
                timeout=10,
            )
        except requests.RequestException as e:
            warn(f"[openrouter_backfill] {generation_id}: request failed (attempt {attempt}): {e}")
            time.sleep(retry_delay)
            continue

        if resp.status_code == 200:
            data = resp.json().get("data") or {}
            return {
                "generation_time": data.get("generation_time"),
                "latency": data.get("latency"),
                "native_tokens_prompt": data.get("native_tokens_prompt"),
                "native_tokens_completion": data.get("native_tokens_completion"),
                "is_byok": data.get("is_byok"),
            }
        if resp.status_code in (404, 429):
            # 404: stats not ready yet. 429: rate limited. Both transient - back off and retry.
            time.sleep(retry_delay)
            continue

        warn(
            f"[openrouter_backfill] {generation_id}: unexpected status "
            f"{resp.status_code}: {resp.text[:200]}"
        )
        return None

    warn(f"[openrouter_backfill] {generation_id}: gave up after {max_retries} attempts")
    return None


def run_backfill(
    token_usage_path: str | Path,
    max_retries: int = DEFAULT_MAX_RETRIES,
    retry_delay: float = DEFAULT_RETRY_DELAY,
    sleep_between: float = DEFAULT_SLEEP_BETWEEN,
    log=None,
) -> dict:
    """Backfill generation stats for every OpenRouter call in token_usage_path.
    Writes (and returns) a dict keyed by response_id, merged into the sibling
    generation_stats.json if one already exists - safe to call repeatedly, only
    ids not already present are fetched. token_usage_path itself is never
    modified; join on response_id when analyzing. No-ops (returns {}) if
    OPENROUTER_API_KEY is unset or the log has no OpenRouter response ids, rather
    than raising - this is meant to run unattended after every trial.
    """

    def info(msg: str):
        if log is not None:
            log.info(msg)
        else:
            print(msg)

    token_usage_path = Path(token_usage_path)
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        info("[openrouter_backfill] OPENROUTER_API_KEY not set - skipping.")
        return {}

    if not token_usage_path.exists():
        info(f"[openrouter_backfill] {token_usage_path} not found - skipping.")
        return {}

    ids = load_openrouter_response_ids(token_usage_path)
    if not ids:
        info("[openrouter_backfill] No OpenRouter response ids ('gen-...') in this log - nothing to backfill.")
        return {}

    out_path = token_usage_path.parent / "generation_stats.json"
    existing: dict = {}
    if out_path.exists():
        try:
            existing = json.loads(out_path.read_text())
        except json.JSONDecodeError:
            existing = {}

    todo = [i for i in ids if i not in existing]
    info(
        f"[openrouter_backfill] {len(ids)} OpenRouter id(s) total, "
        f"{len(existing)} already fetched, {len(todo)} to fetch."
    )

    stats = dict(existing)
    fetched = 0
    for i, gen_id in enumerate(todo):
        result = fetch_generation_stats(gen_id, api_key, max_retries, retry_delay, log=log)
        if result is not None:
            stats[gen_id] = result
            fetched += 1
        if i < len(todo) - 1:
            time.sleep(sleep_between)

    out_path.write_text(json.dumps(stats, indent=2, sort_keys=True))
    info(f"[openrouter_backfill] Wrote {fetched} new / {len(stats)} total entries to {out_path}")
    return stats
