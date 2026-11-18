from __future__ import annotations

import base64
import ipaddress
import json
import re
import shlex

from ..high_level_action import HighLevelAction
from ..LowLevel import RunBashCommand
from incalmo.core.models.events import (
    BashOutputEvent,
    Event,
    HTTPServiceEvent,
)
from incalmo.core.models.network import Host
from incalmo.core.services import (
    AttackGraphService,
    EnvironmentStateService,
    LowLevelActionOrchestrator,
)
from incalmo.core.services.action_context import HighLevelContext
from incalmo.models.agent import Agent


class HTTPServiceImpersonation(HighLevelAction):
    """Operate a generic HTTP responder on a compromised host.

    ``start`` binds an address/port and installs a responder that serves the
    supplied response body or method/path responses, recording requests. ``observe``
    reads requests recorded since the service started. ``stop`` terminates the
    responder and removes an address the action itself added. The action never
    changes routing and never claims that traffic is redirected to it.
    """

    ACTIONS = {"start", "observe", "stop"}
    SCHEMES = {"http"}

    def __init__(
        self,
        host: Host,
        bind_address: str,
        port: int,
        action: str = "start",
        service_id: str | None = None,
        response_body: str | None = None,
        interface: str = "lo",
        scheme: str = "http",
        responses: dict[str, dict] | None = None,
    ):
        super().__init__()
        if not isinstance(host, Host):
            raise ValueError("host must be the compromised Host running the service")
        if not isinstance(port, bool) and isinstance(port, int) and 1 <= port <= 65535:
            self.port = port
        else:
            raise ValueError(f"port must be an integer between 1 and 65535; got {port!r}")
        try:
            self.bind_address = str(ipaddress.IPv4Address(str(bind_address)))
        except ValueError as exc:
            raise ValueError(
                f"bind_address must be an IPv4 address; got {bind_address!r}"
            ) from exc
        if action not in self.ACTIONS:
            raise ValueError(f"action must be one of {sorted(self.ACTIONS)}; got {action!r}")
        if scheme not in self.SCHEMES:
            raise ValueError(
                f"scheme must be one of {sorted(self.SCHEMES)}; TLS is not implemented"
            )
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", str(interface)):
            raise ValueError(f"invalid interface name: {interface!r}")
        if response_body is not None and not isinstance(response_body, str):
            raise ValueError("response_body must be a string when provided")
        if responses is not None:
            if response_body is not None:
                raise ValueError("use responses or response_body, not both")
            if not isinstance(responses, dict):
                raise ValueError(
                    "responses must map 'METHOD /path' to response dictionaries"
                )
            for route, response in responses.items():
                if not isinstance(route, str) or " " not in route:
                    raise ValueError("response keys must be 'METHOD /path'")
                method, path = route.split(" ", 1)
                if (
                    method
                    not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
                    or not path.startswith("/")
                    or any(c in path for c in "?#\r\n ")
                ):
                    raise ValueError(
                        "response keys must use a supported method and a path without a query"
                    )
                if not isinstance(response, dict) or response.keys() - {
                    "status",
                    "headers",
                    "body",
                }:
                    raise ValueError("responses support only status, headers, and body")
                status = response.get("status", 200)
                if (
                    isinstance(status, bool)
                    or not isinstance(status, int)
                    or not 200 <= status <= 599
                ):
                    raise ValueError(
                        "response status must be an integer between 200 and 599"
                    )
                if not isinstance(response.get("body", ""), str):
                    raise ValueError("response body must be a string")
                headers = response.get("headers", {})
                if not isinstance(headers, dict) or any(
                    not isinstance(k, str)
                    or not re.fullmatch(r"[!#$%&'*+.^_\x60|~0-9A-Za-z-]+", k)
                    or not isinstance(v, str)
                    or "\r" in v
                    or "\n" in v
                    for k, v in headers.items()
                ):
                    raise ValueError(
                        "response headers must contain valid names and single-line string values"
                    )
        self.responses = (
            None
            if responses is None
            else {
                route: {**response, "headers": dict(response.get("headers", {}))}
                for route, response in responses.items()
            }
        )
        self.host = host
        self.action = action
        self.scheme = scheme
        self.interface = str(interface)
        self.response_body = response_body if response_body is not None else ""
        raw_id = service_id or f"http-{self.bind_address.replace('.', '-')}-{self.port}"
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", str(raw_id)):
            raise ValueError(
                "service_id must contain only letters, digits, dot, underscore, or hyphen"
            )
        self.service_id = str(raw_id)

    def _agent(self) -> Agent:
        """Prefer a stable elevated identity, but allow ordinary user operations."""
        agents = sorted(
            (agent for agent in self.host.agents if agent is not None),
            key=lambda agent: (
                str(agent.privilege).lower() not in {"elevated", "root"},
                agent.username,
                agent.paw,
            ),
        )
        if not agents:
            raise RuntimeError(
                "HTTP service action requires a C2 agent on the "
                f"compromised host {self.host.hostname or self.host.ip_addresses}"
            )
        return agents[0]

    def _paths(self) -> dict[str, str]:
        base = f"/tmp/incalmo-http-{self.service_id}"
        return {
            "base": base,
            "script": base + ".py",
            "log": base + ".jsonl",
            "pid": base + ".pid",
            "added": base + ".added",
            "out": base + ".out",
        }

    def _server_script(self) -> str:
        paths = self._paths()
        return f'''import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

BIND = {self.bind_address!r}
PORT = {self.port}
BODY = {self.response_body.encode("utf-8")!r}
LOG = {paths["log"]!r}
RESPONSES = {self.responses!r}


def record(handler, body=""):
    with open(LOG, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({{
            "time": time.time(),
            "src": handler.client_address[0],
            "method": handler.command,
            "path": handler.path,
            "headers": dict(handler.headers.items()),
            "body": body,
        }}) + "\\n")
        handle.flush()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def respond(self):
        length = int(self.headers.get("Content-Length", "0"))
        record(self, self.rfile.read(length).decode("utf-8", "replace") if length else "")
        if RESPONSES is None:
            if self.command in ("GET", "HEAD"):
                response = {{"body": BODY, "headers": {{"Content-Type": "text/html; charset=utf-8"}}}}
            elif self.command in ("POST", "PUT", "PATCH"):
                response = {{"body": b"ok\\n", "headers": {{"Content-Type": "text/plain"}}}}
            else:
                response = {{"status": 501, "body": b"unsupported method"}}
        else:
            path = urlsplit(self.path).path
            response = RESPONSES.get(self.command + " " + path)
            if response is None and self.command == "HEAD":
                response = RESPONSES.get("GET " + path)
            if response is None:
                response = {{"status": 404, "body": "not found"}}
        body = response.get("body", "")
        if isinstance(body, str):
            body = body.encode("utf-8")
        headers = dict(response.get("headers", {{}}))
        if not any(name.lower() == "content-type" for name in headers):
            headers["Content-Type"] = "text/html; charset=utf-8"
        status = response.get("status", 200)
        self.send_response(status)
        for name, value in headers.items():
            if name.lower() != "content-length":
                self.send_header(name, value)
        if status not in (204, 304):
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD" and status not in (204, 304):
            self.wfile.write(body)

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = respond


class Server(HTTPServer):
    allow_reuse_address = True


Server((BIND, PORT), Handler).serve_forever()
'''

    async def _run(
        self,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        agent: Agent,
        command: str,
        context: HighLevelContext,
    ) -> tuple[str, str, int | None]:
        events = await low_level_action_orchestrator.run_action(
            RunBashCommand(agent, command), context
        )
        raw = "\n".join(
            event.bash_output for event in events if isinstance(event, BashOutputEvent)
        )
        match = re.search(r"(?m)^__HTTP_RC:(\d+)[ \t]*$", raw)
        rc = int(match.group(1)) if match else None
        cleaned = re.sub(r"(?m)^__HTTP_RC:\d+[ \t]*\n?", "", raw).strip()
        return raw, cleaned, rc

    def _state_command(self) -> str:
        """Check saved process and bind identity before changing service state."""
        paths = self._paths()
        return (
            "pid=\n"
            f"if [ -f {shlex.quote(paths['pid'])} ]; then\n"
            f"  pid=$(cat {shlex.quote(paths['pid'])})\n"
            "  case \"$pid\" in ''|*[!0-9]*) echo __HTTP_PREEXISTING:1; echo 'Invalid service PID' >&2; exit 1;; esac\n"
            "  if [ \"$pid\" -le 1 ]; then echo __HTTP_PREEXISTING:1; echo 'Invalid service PID' >&2; exit 1; fi\n"
            "  if [ -d /proc/\"$pid\" ]; then\n"
            "    args=$(tr '\\000' '\\n' < /proc/\"$pid\"/cmdline)\n"
            "    if [ -z \"$args\" ]; then\n"
            "      pid=\n"
            "    else\n"
            "      echo __HTTP_PREEXISTING:1\n"
            f"      if ! printf '%s\\n' \"$args\" | grep -Fxq -- {shlex.quote(paths['script'])}; then\n"
            "        echo 'Service PID belongs to another process; refusing to change it' >&2\n"
            "        exit 1\n"
            "      fi\n"
            "    fi\n"
            "  else\n"
            "    pid=\n"
            "  fi\n"
            "fi\n"
            f"if [ -f {shlex.quote(paths['script'])} ]; then\n"
            f"  if ! grep -Fxq -- {shlex.quote('BIND = ' + repr(self.bind_address))} {shlex.quote(paths['script'])} || "
            f"! grep -Fxq -- {shlex.quote('PORT = ' + str(self.port))} {shlex.quote(paths['script'])}; then\n"
            "    echo __HTTP_PREEXISTING:1\n"
            "    echo 'Service id belongs to a different address or port' >&2\n"
            "    exit 1\n"
            "  fi\n"
            "fi\n"
        )

    def _listener_command(self) -> str:
        return (
            "listeners=$(ss -H -ltnp)\n"
            f"if ! printf '%s\\n' \"$listeners\" | awk -v endpoint={shlex.quote(self.bind_address + ':' + str(self.port))} "
            "-v pid=\"$pid\" '$4 == endpoint && index($0, \"pid=\" pid \",\") { found=1 } END { exit !found }'; then\n"
            "  echo 'Could not verify that the saved process owns the requested HTTP listener' >&2\n"
            "  exit 1\n"
            "fi\n"
        )

    def _start_command(self) -> str:
        paths = self._paths()
        script = base64.b64encode(self._server_script().encode("utf-8")).decode("ascii")
        address = self.bind_address
        interface = shlex.quote(self.interface)
        return (
            "(\nset -e\n"
            + self._state_command()
            + "if [ -n \"$pid\" ]; then\n"
            f"  if ! printf '%s' {shlex.quote(script)} | base64 -d | cmp -s - {shlex.quote(paths['script'])}; then\n"
            "    echo 'Service id is already running with different content' >&2\n"
            "    exit 1\n"
            "  fi\n"
            + self._listener_command()
            + "  echo ALREADY_RUNNING\n"
            "  echo __HTTP_PID:$pid\n"
            "  echo __HTTP_ADDED:0\n"
            "  exit 0\n"
            "fi\n"
            "added=0\n"
            + (
                "" if address == "0.0.0.0" else (
                    f"if ip -4 addr show | grep -Fq \"inet {address}/\"; then\n"
                    "  :\n"
                    "else\n"
                    f"  ip addr add {address}/32 dev {interface}\n"
                    f"  printf '%s\\n' {interface} > {shlex.quote(paths['added'])}\n"
                    "  added=1\n"
                    "fi\n"
                )
            )
            + f"printf '%s' {shlex.quote(script)} | base64 -d > {shlex.quote(paths['script'])}\n"
            f": > {shlex.quote(paths['log'])}\n"
            f"nohup python3 {shlex.quote(paths['script'])} > {shlex.quote(paths['out'])} 2>&1 &\n"
            f"echo $! > {shlex.quote(paths['pid'])}\n"
            "sleep 1\n"
            f"pid=$(cat {shlex.quote(paths['pid'])})\n"
            "args=$(tr '\\000' '\\n' < /proc/\"$pid\"/cmdline)\n"
            f"printf '%s\\n' \"$args\" | grep -Fxq -- {shlex.quote(paths['script'])}\n"
            + self._listener_command()
            + "echo __HTTP_PID:$pid\n"
            "echo __HTTP_ADDED:$added\n"
            ")\n"
            "__rc=$?\n"
            "echo __HTTP_RC:$__rc\n"
        )

    def _observe_command(self) -> str:
        paths = self._paths()
        return (
            "(\nset -e\n"
            + self._state_command()
            + "running=0\n"
            "if [ -n \"$pid\" ]; then\n"
            + self._listener_command()
            + "  running=1\n"
            "fi\n"
            "echo __HTTP_RUNNING:$running\n"
            f"if [ -f {shlex.quote(paths['log'])} ]; then cat {shlex.quote(paths['log'])}; fi\n"
            ")\n"
            "__rc=$?\n"
            "echo __HTTP_RC:$__rc\n"
        )

    def _stop_command(self) -> str:
        paths = self._paths()
        return (
            "(\nset -e\n"
            + self._state_command()
            + "if [ -n \"$pid\" ]; then\n"
            "  kill \"$pid\"\n"
            "  sleep 1\n"
            + self._state_command()
            + "  if [ -n \"$pid\" ]; then kill -9 \"$pid\"; fi\n"
            "fi\n"
            f"rm -f {shlex.quote(paths['pid'])}\n"
            "present=0\n"
            f"if [ -f {shlex.quote(paths['added'])} ]; then\n"
            f"  owned_interface=$(cat {shlex.quote(paths['added'])})\n"
            "  if [ -z \"$owned_interface\" ]; then echo 'Missing owned address interface' >&2; exit 1; fi\n"
            f"  ip addr del {self.bind_address}/32 dev \"$owned_interface\" || echo 'Address deletion failed; checking residual state' >&2\n"
            "  addresses=$(ip -4 addr show dev \"$owned_interface\")\n"
            f"  if printf '%s\\n' \"$addresses\" | grep -Fq \"inet {self.bind_address}/\"; then\n"
            "    present=1\n"
            "  else\n"
            f"    rm -f {shlex.quote(paths['added'])}\n"
            "  fi\n"
            "fi\n"
            "residual=0\n"
            "listeners=$(ss -ltn)\n"
            f"if printf '%s\\n' \"$listeners\" | grep -Fq \"{self.bind_address}:{self.port} \"; then residual=1; fi\n"
            "echo __HTTP_RESIDUAL:$residual\n"
            "echo __HTTP_ADDRESS_PRESENT:$present\n"
            ")\n"
            "__rc=$?\n"
            "echo __HTTP_RC:$__rc\n"
        )

    def _interactions(self, raw: str) -> list[dict]:
        items: list[dict] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("__HTTP_"):
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                items.append(item)
        return items[-200:]

    async def run(
        self,
        low_level_action_orchestrator: LowLevelActionOrchestrator,
        environment_state_service: EnvironmentStateService,
        attack_graph_service: AttackGraphService,
        context: HighLevelContext,
    ) -> list[Event]:
        agent = self._agent()
        attack_graph_service.record_action(
            self.host, self.host, f"http_service_{self.action}"
        )
        if self.action == "start":
            raw, cleaned, rc = await self._run(
                low_level_action_orchestrator, agent, self._start_command(), context
            )
            pid_match = re.search(r"__HTTP_PID:(\d+)", raw)
            added = "__HTTP_ADDED:1" in raw
            already = "ALREADY_RUNNING" in raw
            ok = rc == 0 and ("__HTTP_PID:" in raw or already)
            if not ok and "__HTTP_PREEXISTING:1" not in raw:
                cleanup_raw, cleanup_clean, _ = await self._run(
                    low_level_action_orchestrator,
                    agent,
                    self._stop_command(),
                    context,
                )
                cleaned = cleaned + "\ncleanup:\n" + cleanup_clean
            return [
                HTTPServiceEvent(
                    self.host,
                    agent,
                    "start",
                    self.bind_address,
                    self.port,
                    scheme=self.scheme,
                    service_id=self.service_id,
                    state="running" if ok else "failed",
                    url=f"{self.scheme}://{self.bind_address}:{self.port}/",
                    pid=int(pid_match.group(1)) if pid_match else None,
                    output=cleaned,
                    local_action_ok=ok,
                    added_address=added,
                    error=None if ok else "HTTP responder did not start or did not listen",
                )
            ]
        if self.action == "observe":
            raw, cleaned, rc = await self._run(
                low_level_action_orchestrator, agent, self._observe_command(), context
            )
            running = re.search(r"(?m)^__HTTP_RUNNING:1[ \t]*$", raw) is not None
            interactions = self._interactions(raw)
            ok = rc == 0
            return [
                HTTPServiceEvent(
                    self.host,
                    agent,
                    "observe",
                    self.bind_address,
                    self.port,
                    scheme=self.scheme,
                    service_id=self.service_id,
                    state=("running" if running else "stopped") if ok else "unknown",
                    url=f"{self.scheme}://{self.bind_address}:{self.port}/",
                    interactions=interactions,
                    output=cleaned,
                    local_action_ok=ok,
                    error=None if ok else "could not verify the HTTP responder or read its interaction log",
                )
            ]
        raw, cleaned, rc = await self._run(
            low_level_action_orchestrator, agent, self._stop_command(), context
        )
        residual = "__HTTP_RESIDUAL:1" in raw
        added_present = "__HTTP_ADDRESS_PRESENT:1" in raw
        ok = rc == 0 and not residual and not added_present
        error = None
        if not ok:
            error = "HTTP responder did not stop cleanly"
            if added_present:
                error += " or its bind address remains"
        return [
            HTTPServiceEvent(
                self.host,
                agent,
                "stop",
                self.bind_address,
                self.port,
                scheme=self.scheme,
                service_id=self.service_id,
                state="stopped" if ok else "failed",
                url=f"{self.scheme}://{self.bind_address}:{self.port}/",
                output=cleaned,
                local_action_ok=ok,
                added_address=added_present,
                error=error,
            )
        ]
