from __future__ import annotations

import json
import shlex
from pathlib import Path
from urllib.parse import urlsplit

from ..high_level_action import HighLevelAction
from ..LowLevel import RunBashCommand
from incalmo.core.models.events import (
    BashOutputEvent,
    ExfiltratedData,
    HTTPResponseEvent,
)
from incalmo.core.models.network import Host


class HTTPRequest(HighLevelAction):
    """Inspect an HTTP service or save its response through a compromised host."""

    def __init__(
        self,
        host: Host,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | None = None,
        username: str | None = None,
        password: str | None = None,
        output_path: str | None = None,
    ):
        super().__init__()
        if not isinstance(host, Host):
            raise ValueError("host must be the compromised Host sending the request")
        target = urlsplit(url)
        if (
            target.scheme != "http"
            or not target.hostname
            or target.username is not None
        ):
            raise ValueError(
                "use an http:// URL without embedded credentials; HTTPS is not implemented"
            )
        if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            raise ValueError("unsupported HTTP method")
        if headers is not None and (
            not isinstance(headers, dict)
            or any(
                not isinstance(k, str) or not isinstance(v, str)
                for k, v in headers.items()
            )
        ):
            raise ValueError("headers must map names to string values")
        if body is not None and not isinstance(body, str):
            raise ValueError("body must be a string")
        if (username is None) != (password is None):
            raise ValueError("username and password must be provided together")
        if username is not None and (
            not isinstance(username, str) or not isinstance(password, str)
        ):
            raise ValueError("username and password must be strings")
        if output_path is not None and (
            not isinstance(output_path, str) or not output_path
        ):
            raise ValueError("output_path must be a nonempty path")
        self.host = host
        self.url, self.method = url, method
        self.headers, self.body = dict(headers or {}), body
        self.username, self.password = username, password
        self.output_path = output_path

    def _command(self) -> str:
        config = {
            "url": self.url,
            "method": self.method,
            "headers": self.headers,
            "body": self.body,
            "username": self.username,
            "password": self.password,
            "output_path": self.output_path,
        }
        script = f"""import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import urllib.error
import urllib.request

config = {config!r}
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

result = {{}}
try:
    headers = dict(config["headers"])
    if config["username"] is not None:
        credentials = (config["username"] + ":" + config["password"]).encode()
        headers["Authorization"] = "Basic " + base64.b64encode(credentials).decode()
    request = urllib.request.Request(
        config["url"], method=config["method"], headers=headers,
        data=config["body"].encode() if config["body"] is not None else None)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({{}}), NoRedirect())
    try:
        response = opener.open(request, timeout=10)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        data = response.read()
        result = {{"status": response.status, "headers": dict(response.headers.items()),
                  "body": data.decode(response.headers.get_content_charset() or "utf-8", "replace")}}
    if config["output_path"] is not None:
        if not 200 <= result["status"] < 300:
            result["error"] = "HTTP response was not successful; no file saved"
        else:
            path = Path(config["output_path"])
            if not path.is_absolute():
                path = Path(pwd.getpwuid(os.getuid()).pw_dir) / path
            with path.open("xb") as handle:
                handle.write(data)
            result["saved_path"] = str(path)
            result["md5"] = hashlib.md5(data).hexdigest()
except (urllib.error.URLError, OSError, ValueError) as exc:
    result["error"] = type(exc).__name__ + ": " + str(exc)
print("__HTTP_RESPONSE__" + json.dumps(result))
"""
        return "python3 -c " + shlex.quote(script)

    async def run(
        self,
        low_level_action_orchestrator,
        environment_state_service,
        attack_graph_service,
        context,
    ):
        agents = sorted(
            (a for a in self.host.agents if a is not None),
            key=lambda a: (
                str(a.privilege).lower() in {"root", "elevated"},
                a.username,
                a.paw,
            ),
        )
        if not agents:
            raise RuntimeError(
                "HTTP request requires a C2 agent on the compromised source host"
            )
        agent = agents[0]
        attack_graph_service.record_action(self.host, self.host, "http_request")
        events = await low_level_action_orchestrator.run_action(
            RunBashCommand(agent, self._command()), context
        )
        raw = "\n".join(e.bash_output for e in events if isinstance(e, BashOutputEvent))
        lines = [
            line[len("__HTTP_RESPONSE__") :]
            for line in raw.splitlines()
            if line.startswith("__HTTP_RESPONSE__")
        ]
        if len(lines) != 1:
            result = {
                "error": "No complete HTTP result from C2; request outcome unknown"
            }
        else:
            try:
                result = json.loads(lines[0])
            except json.JSONDecodeError:
                result = {"error": "Invalid HTTP result from C2"}
        response = HTTPResponseEvent(
            self.host,
            agent,
            self.url,
            self.method,
            status=result.get("status"),
            headers=result.get("headers", {}),
            body=result.get("body", ""),
            saved_path=result.get("saved_path"),
            error=result.get("error"),
        )
        returned = [response]
        if result.get("saved_path") and result.get("md5") and not result.get("error"):
            returned.append(
                ExfiltratedData(Path(result["saved_path"]).name, result["md5"])
            )
        return returned
