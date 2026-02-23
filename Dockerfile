FROM python:3.14-slim
LABEL authors="Boris"

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY core/ ./core

ENTRYPOINT ["fastapi", "run", "./core/main.py"]