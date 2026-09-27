from flask import Flask, jsonify, request
from flask_cors import CORS
import json
import binascii
import logging
import os

from werkzeug.exceptions import BadRequest
from pydantic import ValidationError

from incalmo.c2server.celery.celery_app import make_celery
from incalmo.c2server.routes import (
    agent_bp,
    command_bp,
    strategy_bp,
    logging_bp,
    file_bp,
    environment_bp,
    llm_bp,
    usage_bp,
)
from incalmo.c2server.shared import PAYLOADS_DIR


def _purge_stale_dynamic_payloads():
    """Remove leftover per-command dynamic_payload_*.sh at C2 startup. These are ephemeral —
    written per command from template_payloads/Exec_Bash_Template.sh and normally unlinked when a
    strategy run ends (celery_tasks.py). A crashed/killed run leaves them behind, and under
    c2_on_kali the /incalmo tree (incl. this dir) is shipped to the attacker's own Kali box where a
    recon-capable attacker can read them — a cross-run info leak. Purging on startup guarantees each
    C2 begins with a clean payloads dir even if a prior run didn't clean up. Never touches the tooling
    (sandcat.go, downloadAgent.sh, template_payloads/, exploit scripts) — only the generated glob."""
    n = 0
    for path in PAYLOADS_DIR.glob("dynamic_payload_*.sh"):
        try:
            path.unlink(missing_ok=True)
            n += 1
        except OSError:
            pass
    if n:
        logging.getLogger(__name__).info("Purged %d stale dynamic_payload_*.sh at startup", n)


# Create Flask app
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Configure Flask for Celery
app.config.update(
    broker_url="sqlalchemy+sqlite:////tmp/celery.db",
    result_backend="db+sqlite:////tmp/celery_results.db",
)
celery = make_celery(app)
app.extensions["celery"] = celery

# Disable Flask's default request logging
log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)

# Debug configuration
DEBUG = os.getenv("DEBUG", "false").lower() == "true"
DEBUG_PORT = int(os.getenv("DEBUG_PORT", 5678))

# Register blueprints
app.register_blueprint(agent_bp)
app.register_blueprint(command_bp)
app.register_blueprint(strategy_bp)
app.register_blueprint(logging_bp)
app.register_blueprint(file_bp)
app.register_blueprint(environment_bp)
app.register_blueprint(llm_bp)
app.register_blueprint(usage_bp)


# Error handlers
@app.errorhandler(ValidationError)
def handle_validation_error(exc):
    return jsonify({"error": "Invalid configuration", "details": exc.errors()}), 400


@app.errorhandler(BadRequest)
def handle_bad_request(exc):
    return jsonify({"error": "Invalid JSON payload"}), 400


@app.errorhandler(json.JSONDecodeError)
def handle_json_decode_error(exc):
    return jsonify(
        {
            "error": "Invalid JSON data",
            "message": "The request body contains malformed JSON",
            "details": str(exc),
        }
    ), 400


@app.errorhandler(binascii.Error)
def handle_binascii_error(exc):
    return jsonify(
        {
            "error": "Invalid base64 data",
            "message": "The provided data is not valid base64 encoding",
            "details": str(exc),
        }
    ), 400


@app.errorhandler(UnicodeDecodeError)
def handle_unicode_decode_error(exc):
    return jsonify(
        {
            "error": "Unicode decode error",
            "message": "Failed to decode data to valid UTF-8",
            "details": str(exc),
        }
    ), 400


@app.errorhandler(FileNotFoundError)
def handle_file_not_found(exc):
    return jsonify({"error": "File not found", "message": str(exc)}), 404


@app.errorhandler(ValueError)
def handle_value_error(exc):
    return jsonify({"error": "Invalid value", "message": str(exc)}), 400


@app.errorhandler(KeyError)
def handle_key_error(exc):
    return jsonify(
        {
            "error": "Missing required field",
            "message": f"Required field {exc} is missing",
        }
    ), 400


@app.errorhandler(Exception)
def handle_unexpected_error(exc):
    app.logger.exception(exc)
    return jsonify({"error": "Internal server error"}), 500


@app.errorhandler(404)
def not_found_error(e):
    app.logger.warning(f"404 Not Found: {request.method} {request.url}")
    return "Not Found", 404


# Health check
@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    from incalmo.c2server.shared import running_strategy_tasks

    # Check if Celery workers are available
    inspector = celery.control.inspect()
    active_workers = inspector.active()

    return jsonify(
        {
            "status": "healthy",
            "server": "Flask + Celery",
            "celery_workers": len(active_workers) if active_workers else 0,
            "running_strategies": len(running_strategy_tasks),
            "broker": app.config.get("CELERY_BROKER_URL"),
        }
    ), 200


@app.route("/", methods=["GET"])
def api_root():
    """API root endpoint."""
    return jsonify(
        {
            "message": "Incalmo C2 Server API",
        }
    )


if __name__ == "__main__":
    # if DEBUG:
    #     debugpy.listen(("0.0.0.0", DEBUG_PORT))
    #     debugpy.wait_for_client()

    _purge_stale_dynamic_payloads()  # start clean: drop any per-command payloads a crashed prior run left
    app.run(host="0.0.0.0", port=8888, debug=DEBUG)
