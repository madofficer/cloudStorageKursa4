FROM python:3.14-alpine

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
COPY ./pyproject.toml pyproject.toml
COPY ./uv.lock uv.lock
RUN uv sync

COPY . /app

ENTRYPOINT [ "uv", "run", "uvicorn", "app.main:app", "--port", "8001", "--host", "0.0.0.0"]