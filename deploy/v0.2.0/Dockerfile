FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8780 \
    AGENTPROOF_DB_PATH=/data/agentproof-cloud.db

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir . && \
    mkdir -p /data

EXPOSE 8780

CMD ["sh", "-c", "agentproof cloud-serve --host 0.0.0.0 --port ${PORT:-8780} --db ${AGENTPROOF_DB_PATH:-/data/agentproof-cloud.db}"]
