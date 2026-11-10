"""
Agent-related routes for the C2 server.
Handles agent registration, management, and deletion.
"""

import json
import uuid
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify

from incalmo.models.command import CommandStatus
from incalmo.models.command_result import CommandResult
from incalmo.c2server.shared import (
    agents,
    agent_deletion_queue,
    command_queues,
    command_results,
    decode_base64,
    encode_base64,
    queue_command,
    PAYLOADS_DIR,
)
from incalmo.models.agent import Agent
from incalmo.c2server.shared import AGENT_TIMEOUT_SECONDS

# Create blueprint
agent_bp = Blueprint("agent", __name__)


@agent_bp.route("/beacon", methods=["POST"])
def beacon():
    """Agent check-in endpoint."""
    data = request.data
    decoded_data = decode_base64(data)
    raw_agent_data = json.loads(decoded_data)

    paw = raw_agent_data.get("paw")
    results = raw_agent_data.get("results", [])

    if not paw:
        paw = str(uuid.uuid4())[:8]

    # Store agent info if new
    if paw not in agents and paw not in agent_deletion_queue:
        print(f"New agent: {paw}")
        agents[paw] = Agent(
            paw=paw,
            username=raw_agent_data.get("username"),
            privilege=raw_agent_data.get("privilege"),
            pid=raw_agent_data.get("pid"),
            host_ip_addrs=raw_agent_data.get("host_ip_addrs"),
            hostname=raw_agent_data.get("host"),
        )

    # Update last beacon time for existing agents
    if paw in agents:
        agents[paw].last_beacon = datetime.now()

    # Process any results from previous commands
    for result in results:
        command_id = result.get("id")
        if command_id in command_results:
            result = CommandResult(**result)
            result.output = decode_base64(result.output)
            result.stderr = decode_base64(result.stderr)

            command_results[command_id].result = result
            command_results[command_id].status = CommandStatus.COMPLETED
            payload_file = command_results[command_id].payload_file
            if payload_file is not None:
                (PAYLOADS_DIR / payload_file).unlink(missing_ok=True)

    # Get next command from queue if available
    instructions = []
    if command_queues[paw]:
        next_command = command_queues[paw].pop(0)
        instructions.append(next_command)

    sleep_time = 3
    if paw in agent_deletion_queue:
        del agents[paw]
        del command_queues[paw]
        agent_deletion_queue.remove(paw)
        sleep_time = 10  # Do not beacon for a while to allow for proper deletion

    response = {
        "paw": paw,
        "sleep": sleep_time,
        "watchdog": int(60),
        "instructions": json.dumps([json.dumps(i.display) for i in instructions]),
    }

    encoded_response = encode_base64(response)
    return encoded_response


@agent_bp.route("/agents", methods=["GET"])
def get_agents():
    """Get list of all connected agents."""
    agents_list = []
    for paw, agent in agents.items():
        agents_list.append(agent.model_dump_json())

    return jsonify(agents_list)


@agent_bp.route("/agent/delete/<paw>", methods=["DELETE"])
def delete_agent(paw):
    """Delete a specific agent by sending a kill command."""
    if paw not in agents:
        return jsonify({"error": "Agent not found"}), 404

    # Queue a kill command for the agent
    agent = agents[paw]
    agent_pid = agent.pid

    kill_command = f"(sleep 3 && kill -9 {agent_pid}) &"
    queue_command(paw, kill_command)

    agent_deletion_queue.add(paw)

    return jsonify({"message": f"Agent {paw} deleted successfully"}), 200


@agent_bp.route("/agents/cleanup", methods=["POST"])
def cleanup_stale_agents_manual():
    """Remove agents that haven't beaconed within the timeout period (in-process)."""
    current_time = datetime.now()
    cutoff_time = current_time - timedelta(seconds=AGENT_TIMEOUT_SECONDS)

    stale_agents: list[str] = []

    for paw, agent_data in agents.items():
        last_beacon = agent_data.last_beacon
        if last_beacon < cutoff_time:
            stale_agents.append(paw)

    for paw in stale_agents:
        if paw in agents:
            del agents[paw]
        if paw in command_queues:
            del command_queues[paw]
        if paw in agent_deletion_queue:
            agent_deletion_queue.remove(paw)

    return jsonify({"message": "Stale agents cleaned up successfully"}), 200
