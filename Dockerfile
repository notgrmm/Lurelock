# ==============================================================================
# LureLock Phishing AI — Production Dockerfile
# ==============================================================================
FROM python:3.12-slim

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LURELOCK_PORT=8787

WORKDIR /app

# Install system dependencies (curl for healthchecks)
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files (excluding env/ and caches via .dockerignore)
COPY src/ src/
COPY models/ models/
COPY website/ website/
COPY extension/ extension/
COPY run_server.py main.py ./

# Expose server port
EXPOSE 8787

# Healthcheck endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:8787/health || exit 1

# Start LureLock server
CMD ["python", "run_server.py"]

