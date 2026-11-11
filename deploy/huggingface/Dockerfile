# syntax=docker/dockerfile:1
# Hugging Face Spaces variant of the AgentProof.cloud image.
# Spaces route traffic to port 7860 and expect the README.md metadata at the
# repository root (see docs/huggingface/README.md).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    AGENTPROOF_DATA_DIR=/data \
    PYTHONPATH=/app/src \
    PORT=7860

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY server ./server
COPY site ./site
COPY src ./src

RUN mkdir -p /data
EXPOSE 7860

CMD ["sh", "-c", "uvicorn server.app:app --host 0.0.0.0 --port ${PORT:-7860}"]
