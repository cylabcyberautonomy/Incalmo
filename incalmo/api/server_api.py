from incalmo.core.actions.low_level_action import LowLevelAction
from incalmo.models.agent import Agent
from incalmo.core.services.config_service import ConfigService
from config.attacker_config import AttackerConfig
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import json
import time
from incalmo.models.command_result import CommandResult
from incalmo.models.command import Command, CommandStatus
from incalmo.core.models.network import Network
from incalmo.models.llm_agent_action_data import LLMAgentActionData


# (connect_timeout, read_timeout) per request: a BLACK-HOLED tunnel (packets dropped, no RST) must
# fail-and-retry, not hang the whole attacker forever waiting on a dead socket.
_HTTP_TIMEOUT = (10, 60)


class _TimeoutSession(requests.Session):
    """Session that applies _HTTP_TIMEOUT to every request unless one is passed explicitly, so no
    bare call can hang forever on a black-holed tunnel."""
    def request(self, *args, **kwargs):
        kwargs.setdefault("timeout", _HTTP_TIMEOUT)
        return super().request(*args, **kwargs)


class _LoggingRetry(Retry):
    """Retry that LOGS every retry event to stdout (-> attacker.log). Silent retries hid whether a
    run's tunnel was dropping: a bridged drop left no trace, so a run that limped along in backoff
    and then hit the wall-clock cap looked identical to one doing genuine work. Now each retry prints
    a timestamped '[c2-retry]' line naming the failure, so post-hoc we can count drops and sum the
    time a run actually lost to the tunnel — distinguishing a genuine 45-min attack from a stall."""
    def increment(self, method=None, url=None, response=None, error=None, _pool=None, _stacktrace=None):
        try:
            reason = error if error is not None else (f"HTTP {response.status}" if response is not None else "unknown")
            print(f"[c2-retry] {time.strftime('%Y-%m-%d %H:%M:%S')} {method} {url} — bridging failure: {reason}",
                  flush=True)
        except Exception:
            pass
        # self.new() (used inside super().increment) preserves type(self), so logging persists across retries
        return super().increment(method, url, response, error, _pool, _stacktrace)


def _build_session() -> requests.Session:
    """A requests.Session whose adapter retries transient C2 unavailability instead of letting a
    single failure crash the (often hour-long) attacker run. Under c2_on_kali the client reaches the
    C2 through an ssh -L tunnel over a contended bastion/FIP; the tunnel occasionally drops and its
    supervisor reconnects within seconds — but a bare requests.get during that gap raises
    ConnectionError([Errno 111]) and the attacker exits 1, discarding all the LLM spend already
    incurred. Retry policy:
      * connect=12  — a REFUSED/failed CONNECT means the server never saw the request, so retrying is
                      always safe (even for POST); this is the dominant tunnel-gap case. With backoff
                      it rides out multi-minute reconnect windows.
      * read=2      — a failure AFTER the request was sent could double-execute a non-idempotent POST
                      (send_command), so keep this small.
      * status 502/503/504 — transient C2/proxy errors.
    backoff_factor grows the delay (capped at urllib3's 120s) so a long outage waits, not spins."""
    retry = _LoggingRetry(
        total=12, connect=12, read=2, status=3,
        backoff_factor=1.5, status_forcelist=(502, 503, 504),
        allowed_methods=None,          # retry all methods (POSTs need connect-retries); read=2 bounds POST risk
        raise_on_status=False, respect_retry_after_header=True,
    )
    s = _TimeoutSession()
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


class C2ApiClient:
    def __init__(self):
        self.server_url = ConfigService().get_config().c2c_server
        self._session = _build_session()

    def get_agent(self, paw: str) -> Agent | None:
        """Fetch a specific agent by its unique identifier (PAW)"""
        response = self._session.get(f"{self.server_url}/agents")
        if response.ok:
            agent_data = response.json()
            for agent_data in agent_data:
                agent = Agent.model_validate_json(agent_data)
                if paw == agent.paw:
                    return agent
            return None
        else:
            raise Exception(
                f"Failed to get agent {paw}: {response.status_code} {response.text}"
            )

    def get_agents(self) -> list[Agent]:
        """Fetch a list of agent information"""
        agent_list = []
        response = self._session.get(f"{self.server_url}/agents")
        if response.ok:
            agents = response.json()
            for agent_data in agents:
                agent = Agent.model_validate_json(agent_data)
                agent_list.append(agent)
            return agent_list
        else:
            raise Exception(
                f"Failed to get agents: {response.status_code} {response.text}"
            )

    def get_llm_agent_action(self) -> LLMAgentActionData | None:
        """Fetch the next LLM Agent action from the queue"""
        response = self._session.get(f"{self.server_url}/get_llm_agent_action")
        if response.ok:
            action_data = response.json()
            return LLMAgentActionData(**action_data)
        else:
            return None

    def send_command(self, low_level_action: LowLevelAction) -> CommandResult:
        """Send a command to an agent and poll for results."""
        # Send the command
        payload = {
            "agent": low_level_action.agent.paw,
            "command": low_level_action.command,
            "payloads": low_level_action.payloads,
        }
        headers = {"Content-Type": "application/json"}
        response = self._session.post(
            f"{self.server_url}/send_command", data=json.dumps(payload), headers=headers
        )

        if not response.ok:
            raise Exception(
                f"Failed to send command: {response.status_code} {response.text}"
            )

        # Get command ID from initial response
        command = Command(**response.json())
        if not command:
            raise Exception("No command ID received from server")

        # Poll for results
        max_attempts = 45  # 45 seconds timeout
        poll_interval = 1  # 1 second between polls

        for _ in range(max_attempts):
            status_response = self._session.get(
                f"{self.server_url}/command_status/{command.id}"
            )

            if not status_response.ok:
                raise Exception(
                    f"Failed to check command status: {status_response.status_code} {status_response.text}"
                )

            command = Command(**status_response.json())
            if command.status == CommandStatus.COMPLETED and command.result:
                return command.result

            time.sleep(poll_interval)

        # Return a timeout result instead of raising an exception
        return CommandResult(
            exit_code="timeout",
            id=command.id,
            output="",
            pid=0,
            status="timeout",
            stderr=f"Command polling timed out after {max_attempts} seconds",
        )

    def report_environment_state(self, network: Network):
        """Report the environment state."""
        url = f"{self.server_url}/update_environment_state"
        hosts = network.get_all_unique_hosts()
        payload = {"hosts": [host.to_dict() for host in hosts]}
        response = self._session.post(
            url,
            json=payload,
            headers={"Content-Type": "application/json"},
        )

        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to report environment state: {response.text}")

    def get_queued_llm_agent_action(self):
        """Fetch all queued LLM Agent action."""
        response = self._session.get(f"{self.server_url}/get_llm_agent_action")
        if response.ok:
            action_data = response.json()
            return LLMAgentActionData(**action_data)
        else:
            raise Exception(
                f"Failed to get queued LLM Agent actions: {response.status_code} {response.text}"
            )

    def incalmo_startup(self, config: AttackerConfig):
        """Start incalmo with full AttackerConfig"""
        url = f"{self.server_url}/startup"

        response = self._session.post(
            url,
            json=config.model_dump(),
            headers={"Content-Type": "application/json"},
        )

        if response.status_code in [200, 202]:
            print("Incalmo started successfully")
            return response.json()
        else:
            raise Exception(f"Failed to start Incalmo: {response.text}")
