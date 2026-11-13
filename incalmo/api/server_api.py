from incalmo.core.actions.low_level_action import LowLevelAction
from incalmo.models.agent import Agent
from config.attacker_config import AttackerConfig
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import time
from incalmo.models.command_result import CommandResult
from incalmo.models.command import Command, CommandStatus
from incalmo.core.models.network import Network
from incalmo.models.llm_agent_action_data import LLMAgentActionData


# (connect_timeout, read_timeout) per request: a BLACK-HOLED tunnel (packets dropped, no RST) must
# fail-and-retry, not hang the whole attacker forever waiting on a dead socket.
_HTTP_TIMEOUT = (10, 60)


class C2UnavailableError(requests.ConnectionError):
    """C2 communication failed; a submitted command may still be executing."""

    def __init__(self, message: str, command_id: str | None = None):
        super().__init__(message)
        self.command_id = command_id


class _TimeoutSession(requests.Session):
    """Apply a request timeout and identify exhausted C2 transport failures."""

    def request(self, *args, **kwargs):
        kwargs.setdefault("timeout", _HTTP_TIMEOUT)
        try:
            return super().request(*args, **kwargs)
        except requests.RequestException as exc:
            raise C2UnavailableError(f"C2 request failed: {exc}") from exc


class _LoggingRetry(Retry):
    """Log C2 request failures without assuming a tunnel is their cause."""

    def increment(self, method=None, url=None, response=None, error=None, _pool=None, _stacktrace=None):
        reason = error if error is not None else (f"HTTP {response.status}" if response is not None else "unknown")
        print(f"[c2-retry] {time.strftime('%Y-%m-%d %H:%M:%S')} {method} {url} — C2 request failed: {reason}",
              flush=True)
        return super().increment(method, url, response, error, _pool, _stacktrace)


def _build_session() -> requests.Session:
    """Retry safe reads and pre-submission connection failures.

    A lost POST response may follow successful queueing. Do not repeat a
    mutation after a read failure or HTTP error.
    """
    retry = _LoggingRetry(
        total=12, connect=12, read=2, status=3,
        backoff_factor=1.5, status_forcelist=(502, 503, 504),
        allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
        raise_on_status=False, respect_retry_after_header=True,
    )
    s = _TimeoutSession()
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


class C2ApiClient:
    def __init__(self):
        from incalmo.core.services.config_service import ConfigService

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

    def get_command_status(self, command_id: str) -> Command:
        """Read a submission without consuming its eventual result."""
        try:
            response = self._session.get(f"{self.server_url}/command_status/{command_id}")
        except C2UnavailableError as exc:
            raise C2UnavailableError(
                f"Cannot observe command {command_id}; execution outcome unknown: {exc}",
                command_id=command_id,
            ) from exc
        if not response.ok:
            raise C2UnavailableError(
                f"Cannot observe command {command_id}: HTTP {response.status_code}; execution outcome unknown",
                command_id=command_id,
            )
        return Command(**response.json())

    def send_command(self, low_level_action: LowLevelAction) -> CommandResult:
        """Submit once, then poll; expiration does not cancel the instruction."""
        payload = {
            "agent": low_level_action.agent.paw,
            "command": low_level_action.command,
            "payloads": low_level_action.payloads,
        }
        try:
            response = self._session.post(
                f"{self.server_url}/send_command", json=payload,
            )
        except C2UnavailableError as exc:
            raise C2UnavailableError(f"Command submission failed; acceptance unknown: {exc}") from exc
        if response.status_code >= 500:
            raise C2UnavailableError(
                f"Command submission returned HTTP {response.status_code}; acceptance unknown"
            )
        if not response.ok:
            raise Exception(
                f"Failed to send command: {response.status_code} {response.text}"
            )
        command = Command(**response.json())
        command_id = command.id
        max_attempts = 45
        started = time.monotonic()
        for _ in range(max_attempts):
            command = self.get_command_status(command_id)
            if command.status == CommandStatus.COMPLETED and command.result:
                return command.result
            time.sleep(1)

        return CommandResult(
            exit_code="timeout", id=command_id, output="", pid=0, status="timeout",
            stderr=f"Command polling exhausted after {max_attempts} polls ({time.monotonic() - started:.1f}s); execution outcome unknown",
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
