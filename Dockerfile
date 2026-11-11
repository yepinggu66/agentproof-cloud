# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    AGENTPROOF_DATA_DIR=/data \
    PYTHONPATH=/app/src \
    PORT=8080

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# The commercial service (server/) imports the merged library package
# (src/agentproof/scanner/engine.py), so both trees ship in the image.
COPY server ./server
COPY site ./site
COPY src ./src

RUN mkdir -p /data
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=4s --start-period=8s --retries=3 \
  CMD python -c "import os,sys,urllib.request; port=os.environ.get('PORT','8080'); sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health', timeout=3).status==200 else 1)"

CMD ["sh", "-c", "uvicorn server.app:app --host 0.0.0.0 --port ${PORT:-8080}"]
