# Sentinel Scan reporting server.
#
# Build:  docker build -f server/Dockerfile -t sentinel-server .
# Run:    docker run -p 8000:8000 -v sentinel-data:/data sentinel-server
#
# Build context is the repository root so the server package can be copied.

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies first so the layer caches across source changes.
COPY requirements.txt ./
RUN pip install --no-cache-dir \
        "fastapi>=0.110" \
        "uvicorn[standard]>=0.29" \
        "sqlalchemy>=2.0" \
        "pydantic>=2.6" \
        "python-multipart>=0.0.9"

COPY server/ ./server/

# Run as a non-root user. This process stores live malware samples; if it is
# ever compromised, the blast radius should be one unprivileged account with
# access to one data directory.
RUN useradd --create-home --uid 10001 sentinel \
    && mkdir -p /data/samples \
    && chown -R sentinel:sentinel /data /app

USER sentinel

ENV SENTINEL_SERVER_DB_URL=sqlite:////data/sentinel-server.db \
    SENTINEL_SERVER_SAMPLE_DIR=/data/samples \
    SENTINEL_SERVER_HOST=0.0.0.0 \
    SENTINEL_SERVER_PORT=8000

VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"

CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000"]
