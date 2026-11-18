#!/bin/bash
set -e

CELERY_STATE_DIR="/tmp/celery_state"
mkdir -p "$CELERY_STATE_DIR"
chmod 777 "$CELERY_STATE_DIR"

cd /incalmo

uv run --frozen --no-sync celery -A incalmo.c2server.celery.celery_worker worker \
  --concurrency=1 \
  --statedb "$CELERY_STATE_DIR/celery.db" &

uv run --frozen --no-sync celery -A incalmo.c2server.celery.celery_worker beat \
  --schedule "$CELERY_STATE_DIR/celerybeat-schedule" &

sleep 3
uv run --frozen --no-sync ./incalmo/c2server/c2server.py
