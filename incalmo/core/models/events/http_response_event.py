from incalmo.core.models.events import Event


class HTTPResponseEvent(Event):
    """HTTP response observed from a compromised source host, or an explicit error."""

    def __init__(
        self,
        host,
        agent,
        url,
        method,
        *,
        status=None,
        headers=None,
        body="",
        saved_path=None,
        error=None,
    ):
        self.host, self.agent = host, agent
        self.url, self.method = url, method
        self.status, self.headers = status, dict(headers or {})
        self.body, self.saved_path, self.error = body, saved_path, error

    def __str__(self):
        lines = [
            f"HTTPResponseEvent: {self.method} {self.url}",
            f"source agent={self.agent.paw} user={self.agent.username}",
            f"status={self.status}",
            f"headers={self.headers}",
        ]
        if self.saved_path:
            lines.append(f"saved_path={self.saved_path}")
        if self.error:
            lines.append(f"error={self.error}")
        lines.append("body:\n" + self.body)
        return "\n".join(lines)
