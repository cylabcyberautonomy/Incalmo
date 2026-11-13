FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

ENV PYTHONUNBUFFERED=1 UV_PROJECT_ENVIRONMENT=/opt/incalmo-venv
WORKDIR /incalmo

COPY pyproject.toml uv.lock README.md ./
COPY config/attacker_config.py ./config/attacker_config.py
COPY docker/c2server/start.sh ./docker/c2server/start.sh
COPY incalmo ./incalmo
RUN uv sync --frozen --no-dev

EXPOSE 8888
CMD ["bash", "docker/c2server/start.sh"]
