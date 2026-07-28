# Multi-stage: the compiler toolchain some wheels need never reaches the
# final image, which keeps it small and shrinks the attack surface.
#
# The base image is pinned to a patch version. To pin it by digest instead
# (fully reproducible), resolve it once and replace the tag:
#   docker buildx imagetools inspect python:3.12.6-slim
#   FROM python:3.12.6-slim@sha256:<digest>
FROM python:3.12.6-slim AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
# Dependencies first (takes advantage of Docker's layer cache)
COPY requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt


FROM python:3.12.6-slim

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY app ./app

# Run as an unprivileged user instead of root, and let it own the history
# volume mount point.
RUN useradd --create-home --uid 10001 ariadne \
    && mkdir -p /data \
    && chown -R ariadne:ariadne /app /data
USER ariadne

EXPOSE 8000

# /health already existed but nothing was checking it.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
