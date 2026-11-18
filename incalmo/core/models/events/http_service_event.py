import json

from incalmo.core.models.events import Event


class HTTPServiceEvent(Event):
    """Observable result of a high-level HTTP service lifecycle action.

    Starting a service only binds a listener and installs its observations; it
    does not alter routing or prove that traffic is redirected to it. Interaction
    entries are recorded by the responder on the compromised host and include
    the source address, method, path, headers, and request body.
    """

    def __init__(
        self,
        host,
        agent,
        operation: str,
        bind_address: str,
        port: int,
        *,
        scheme: str = "http",
        service_id: str = "",
        state: str | None = None,
        url: str | None = None,
        pid: int | None = None,
        interactions: list[dict] | None = None,
        output: str = "",
        local_action_ok: bool | None = None,
        added_address: bool = False,
        error: str | None = None,
    ):
        self.host = host
        self.agent = agent
        self.operation = operation
        self.bind_address = bind_address
        self.port = port
        self.scheme = scheme
        self.service_id = service_id
        self.state = state
        self.url = url
        self.pid = pid
        self.interactions = interactions if interactions is not None else []
        self.output = output
        self.local_action_ok = local_action_ok
        self.added_address = added_address
        self.error = error

    def __str__(self) -> str:
        host = getattr(self.host, "hostname", None) or getattr(
            self.host, "ip_addresses", []
        )
        fields = [
            f"HTTPServiceEvent: {self.operation}",
            f"host={host}",
            f"agent={getattr(self.agent, 'paw', '')}",
            f"user={getattr(self.agent, 'username', '')}",
            f"service_id={self.service_id}",
            f"scheme={self.scheme}",
            f"bind={self.bind_address}:{self.port}",
        ]
        if self.url is not None:
            fields.append(f"url={self.url}")
        if self.state is not None:
            fields.append(f"state={self.state}")
        if self.pid is not None:
            fields.append(f"pid={self.pid}")
        if self.local_action_ok is not None:
            fields.append(f"local_action_ok={self.local_action_ok}")
        if self.added_address:
            fields.append("added_address=True")
        if self.error:
            fields.append(f"error={self.error}")
        if self.interactions:
            fields.append("interactions:")
            fields.append(json.dumps(self.interactions, indent=2))
        fields.append("output:")
        fields.append(self.output or "(no output)")
        return "\n".join(fields)
