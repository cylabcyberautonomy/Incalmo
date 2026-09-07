import base64
import json

from ..low_level_action import LowLevelAction
from incalmo.models.agent import Agent
from incalmo.models.command_result import CommandResult
from incalmo.core.models.events import Event


class MsfRpcCommand(LowLevelAction):
    """Dispatches one Metasploit RPC operation to run on the agent's host, via
    msf_rpc_client.py (see incalmo/c2server/payloads/msf_rpc_client.py for why
    this can't be a direct MetasploitService call from the harness side: the
    Kali VM's msfrpcd is only reachable from Kali itself).

    Callers (llm_ms_lateral_move.py) read `.stdout`/`.stderr` after awaiting
    run_action() - this emits no Incalmo Events itself, it's raw RPC plumbing
    for the LLM lateral-movement agent's own conversation loop, not something
    the rest of Incalmo's event/state model needs to know about.
    """

    def __init__(self, agent: Agent, op: str, args: dict):
        self.op = op
        self.args = args
        self.stdout: str = ""
        self.stderr: str = ""

        # base64, not raw JSON, in the command string: a JSON arg (nested quotes,
        # braces, spaces) surviving a dispatched shell command string intact isn't
        # something to rely on - see msf_rpc_client.py's own docstring.
        encoded_args = base64.b64encode(json.dumps(args).encode()).decode()
        command = f"python3 msf_rpc_client.py {op} {encoded_args}"
        payloads = ["msf_rpc_client.py"]

        super().__init__(agent, command, payloads, command_delay=1)

    async def get_result(self, result: CommandResult) -> list[Event]:
        self.stdout = result.output
        self.stderr = result.stderr
        return []
