"""Command submission and UUID-addressed result lookup for the C2 server."""

import json
from flask import Blueprint, request, jsonify

from incalmo.c2server.shared import agents, command_results, queue_command

command_bp = Blueprint("command", __name__)


@command_bp.route("/send_manual_command", methods=["POST"])
def send_manual_command():
    """Send a manual command using the same lifecycle as an API command."""
    data = json.loads(request.data)
    agent, command = data.get("agent"), data.get("command")
    if not agent or not command:
        return jsonify({"error": "Missing agent or command"}), 400
    if agent not in agents:
        return jsonify({"error": "Agent not found"}), 404
    return jsonify(queue_command(agent, command).model_dump())


@command_bp.route("/send_command", methods=["POST"])
def send_command():
    """Send a command to a specific agent."""
    data = json.loads(request.data)
    agent, command = data.get("agent"), data.get("command")
    if not agent or not command:
        return jsonify({"error": "Missing agent or command"}), 400
    if agent not in agents:
        return jsonify({"error": "Agent not found"}), 404
    return jsonify(queue_command(agent, command, data.get("payloads", [])).model_dump())


@command_bp.route("/command_status/<command_id>", methods=["GET"])
def check_command_status(command_id):
    """Return a command and any eventual result without consuming it."""
    if command_id not in command_results:
        return jsonify({"error": "Command not found"}), 404
    return jsonify(command_results[command_id].model_dump())
