# LLM Scanner API image.
#   docker build -t llm-scanner-api .
#   docker run -p 8000:8000 -v llmscanner-data:/data \
#     -e ENV=production -e SECRET_KEY=... -e GROQ_API_KEY=... llm-scanner-api

# ── Build stage: install dependencies into a virtualenv ───────
FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


# ── Runtime stage ─────────────────────────────────────────────
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl libffi8 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1001 appuser \
    && mkdir -p /data && chown appuser:appuser /data

# The virtualenv lives outside /root, so the non-root user can use it.
COPY --from=builder /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    DB_PATH=/data/llmscanner.db \
    REPORTS_DIR=/data/reports

WORKDIR /app
COPY --chown=appuser:appuser backend/ backend/

USER appuser
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

# One worker: scans run in this process. --proxy-headers lets rate limits see the
# real client IP behind a reverse proxy; set FORWARDED_ALLOW_IPS to that proxy's IP.
CMD ["uvicorn", "api:app", "--app-dir", "backend", "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "1", "--proxy-headers"]
