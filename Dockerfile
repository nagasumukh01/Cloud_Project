# TrustProof-Cloud - CPU-only image. No GPU, no paid base image, no build secrets.
# NOTE: authored but NOT executed in the development sandbox (no Docker daemon available).
# See docs/deployment.md A3 before reporting this as verified.

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    TPC_DATA_DIR=/app/data

WORKDIR /app

# Dependencies first so layer caching survives source edits.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY crypto/ ./crypto/
COPY ml/ ./ml/
COPY services/ ./services/
COPY simulator/ ./simulator/
COPY experiments/ ./experiments/
COPY scripts/ ./scripts/
COPY tests/ ./tests/
COPY pyproject.toml Makefile ./

# Warm the model cache at build time so the first request is not slowed by training,
# and so the container works with no network at runtime.
RUN mkdir -p /app/data/models && \
    python -c "from ml.inference_model import get_model; m=get_model(cache_dir='/app/data/models'); print('cached', m.version, m.test_accuracy)"

# Run as a non-root user. Keys and the database live under /app/data.
RUN useradd --create-home --uid 10001 tpc && chown -R tpc:tpc /app
USER tpc

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status==200 else 1)"

CMD ["uvicorn", "services.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
