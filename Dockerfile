FROM python:3.14-slim

LABEL maintainer="Corey A. Wade <corey@cwccie.com>"
LABEL description="SentinelForge — Autonomous SOC Analyst Platform"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
COPY sample_data/ sample_data/
COPY playbooks/ playbooks/

# Install package with all dependencies
RUN pip install --no-cache-dir ".[all]"

# Expose dashboard port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=5s \
    CMD curl -f http://localhost:5000/api/v1/metrics || exit 1

# Default: run demo then start dashboard
CMD ["sentinelforge", "dashboard", "--host", "0.0.0.0"]
