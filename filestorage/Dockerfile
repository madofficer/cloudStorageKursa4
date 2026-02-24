FROM python:3.14-alpine
LABEL authors="Matthew"

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
COPY ./pyproject.toml pyproject.toml
RUN uv sync

COPY main.py main.py
ENTRYPOINT [ "uv", "run", "uvicorn", "main:app", "--port", "8000", "--host", "0.0.0.0" ]