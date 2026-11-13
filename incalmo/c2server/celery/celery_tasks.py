from incalmo.incalmo_runner import run_incalmo_strategy
from config.attacker_config import AttackerConfig
import asyncio
import os
import requests

from incalmo.c2server.celery.celery_worker import celery_worker
from incalmo.c2server.shared import (
    TaskState,
)


@celery_worker.task(bind=True, name="run_incalmo_strategy_task")
def run_incalmo_strategy_task(self, config_dict: dict):
    config = AttackerConfig(**config_dict)
    if not config.id:
        raise Exception("No task ID specified")

    # Run the strategy
    task_id = config.id
    asyncio.run(run_incalmo_strategy(config, task_id))

    return {"status": str(TaskState.SUCCESS)}


@celery_worker.task(bind=True, name="cancel_strategy_task")
def cancel_strategy_task(self, task_id: str):
    """Cancel a running strategy task."""
    celery_worker.control.revoke(task_id, terminate=True, signal="SIGTERM")
    return {"status": str(TaskState.SUCCESS), "message": f"Task {task_id} cancelled"}


# Note: Periodic tasks are now configured directly in celery_worker.py
# using beat_schedule configuration instead of signals


@celery_worker.task(bind=True, name="trigger_cleanup_on_server")
def trigger_cleanup_on_server(self):
    """Trigger cleanup on the Flask server so it has access to in-process state."""
    server_url = os.environ.get("C2C_SERVER_URL", "http://localhost:8888")
    try:
        requests.post(f"{server_url}/agents/cleanup", timeout=10)
    # Catch server down exception Flask could be booting up)
    except requests.exceptions.RequestException:
        pass
