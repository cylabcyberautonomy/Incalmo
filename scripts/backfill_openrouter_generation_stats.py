#!/usr/bin/env python3
"""CLI wrapper around incalmo.core.services.openrouter_backfill.run_backfill.

Since Incalmo v?.? this runs automatically at the end of every trial (see
LLMStrategy.finished_cb) - use this manually only to re-run against an older log,
or one from a run that predates the automatic hook.

Usage:
    python scripts/backfill_openrouter_generation_stats.py output/<operation_id>/token_usage.json

See incalmo/core/services/openrouter_backfill.py for the retention caveat and
exactly which fields get backfilled, and where.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from incalmo.core.services.openrouter_backfill import (  # noqa: E402
    DEFAULT_MAX_RETRIES,
    DEFAULT_RETRY_DELAY,
    DEFAULT_SLEEP_BETWEEN,
    run_backfill,
)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("token_usage_path", type=Path, help="Path to a run's token_usage.json")
    parser.add_argument("--max-retries", type=int, default=DEFAULT_MAX_RETRIES)
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=DEFAULT_RETRY_DELAY,
        help="Seconds between retries for a not-yet-ready or rate-limited id",
    )
    parser.add_argument(
        "--sleep-between",
        type=float,
        default=DEFAULT_SLEEP_BETWEEN,
        help="Seconds between distinct ids, to stay under rate limits",
    )
    args = parser.parse_args()

    run_backfill(
        args.token_usage_path,
        max_retries=args.max_retries,
        retry_delay=args.retry_delay,
        sleep_between=args.sleep_between,
    )


if __name__ == "__main__":
    main()
