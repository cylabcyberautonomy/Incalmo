"""
File-related routes for the C2 server.
Handles file downloads for payloads and agents.
"""

from pathlib import Path

from flask import Blueprint, request, jsonify

from incalmo.c2server.shared import BASE_DIR, AGENTS_DIR


def _safe_file_name(name: str) -> str:
    """Reject traversal/absolute paths; all served files live directly in a payload directory."""
    if not name or name in {".", ".."} or Path(name).name != name or "\\" in name:
        raise ValueError("invalid file name")
    return name

# Create blueprint
file_bp = Blueprint("file", __name__)


@file_bp.route("/file/download", methods=["POST"])
def download():
    """Download a file from the payloads directory."""
    file_name = request.headers.get("File")

    if not file_name:
        return jsonify({"error": "Missing file name"}), 400

    try:
        file_name = _safe_file_name(file_name)
    except ValueError:
        return jsonify({"error": "Invalid file name"}), 400

    # Try both payload directories
    file_path = BASE_DIR / "payloads" / file_name
    if not file_path.exists():
        return jsonify({"error": "File not found"}), 404

    file_data = file_path.read_bytes()

    headers = {
        "Content-Disposition": f'attachment; filename="{file_name}"',
        "FILENAME": file_name,
    }

    return file_data, 200, headers


@file_bp.route("/agent/download", methods=["POST"])
def agent_download():
    """Download a file from the agents directory."""
    file_name = request.headers.get("File")

    if not file_name:
        return jsonify({"error": "Missing file name"}), 400

    try:
        file_name = _safe_file_name(file_name)
    except ValueError:
        return jsonify({"error": "Invalid file name"}), 400

    file_path = AGENTS_DIR / file_name
    if not file_path.exists():
        return jsonify({"error": "File not found"}), 404

    file_data = file_path.read_bytes()

    headers = {
        "Content-Disposition": f'attachment; filename="{file_name}"',
        "FILENAME": file_name,
    }

    return file_data, 200, headers
