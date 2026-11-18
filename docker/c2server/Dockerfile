FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

ENV PYTHONUNBUFFERED=1 UV_PROJECT_ENVIRONMENT=/opt/incalmo-venv
WORKDIR /incalmo

COPY pyproject.toml uv.lock README.md ./
COPY config/attacker_config.py ./config/attacker_config.py
COPY docker/c2server/start.sh ./docker/c2server/start.sh
COPY incalmo ./incalmo
RUN uv sync --frozen --no-dev
# The C2 server's strategy actions use ConfigService, which requires this file. The runtime
# environment overrides the C2/agent URLs; no host repository or credential mount is used.
RUN mkdir -p config \
    && printf '%s\n' '{"name":"c2","strategy":{"planning_llm":"haiku3_5_strategy","execution_llm":"claude-3.5-haiku","abstraction":"incalmo"},"environment":"equifax_large","c2c_server":"http://127.0.0.1:8888","blacklist_ips":["172.17.0.0/16"]}' > config/config.json \
    && useradd --create-home --shell /usr/sbin/nologin c2 \
    && chown -R c2:c2 /incalmo
USER c2

EXPOSE 8888
CMD ["bash", "docker/c2server/start.sh"]
