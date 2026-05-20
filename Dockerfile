# ── Build Stage ───────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


# ── Runtime Stage ─────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# System deps for reportlab / pillow
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl libffi8 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy application code
COPY . .

# Persistent data directory (mount a volume here on Railway)
RUN mkdir -p /data && ln -sfn /data results

# Non-root user
RUN useradd -m -u 1001 appuser && \
    chown -R appuser:appuser /app /data
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
