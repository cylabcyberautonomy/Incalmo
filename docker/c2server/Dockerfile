FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

ENV PYTHONUNBUFFERED=1 UV_PROJECT_ENVIRONMENT=/opt/incalmo-venv
WORKDIR /incalmo

COPY . .
RUN uv sync --frozen --no-dev

EXPOSE 8888
CMD ["bash", "docker/c2server/start.sh"]
