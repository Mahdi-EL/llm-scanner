# ── Base Image ────────────────────────────────────────────────
FROM python:3.11-slim

# ── Set Working Directory ─────────────────────────────────────
WORKDIR /app

# ── Install System Dependencies ───────────────────────────────
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# ── Copy Requirements First (for cache) ──────────────────────
COPY requirements.txt .

# ── Install Python Dependencies ───────────────────────────────
RUN pip install --no-cache-dir -r requirements.txt

# ── Copy All Project Files ────────────────────────────────────
COPY . .

# ── Create Results Directory ──────────────────────────────────
RUN mkdir -p results

# ── Expose Port ───────────────────────────────────────────────
EXPOSE 8000

# ── Start Command ─────────────────────────────────────────────
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]