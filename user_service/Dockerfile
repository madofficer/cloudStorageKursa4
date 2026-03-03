FROM ghcr.io/astral-sh/uv:python3.13-slim
LABEL authors="Boris"



WORKDIR /app

RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project \

COPY . /app



ENTRYPOINT []

CMD ["uv", "ruv", "uvicorn", "fastapi", "dev", "--host", "127.0.0.1", "user_service"]