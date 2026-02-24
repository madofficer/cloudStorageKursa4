FROM python:3.14-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-dev

FROM python:3.14-slim AS runner

COPY --from=builder --chown=app:app /app/.venv /app/.venv

WORKDIR /app

COPY . .

ENTRYPOINT [ "/app/.venv/bin/uvicorn", "app.main:app", "--port", "8000", "--host", "0.0.0.0" ]
