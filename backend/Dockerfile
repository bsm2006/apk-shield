FROM python:3.11-slim

WORKDIR /app

# Install system dependencies needed for androguard + lxml
RUN apt-get update && apt-get install -y \
    build-essential \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --timeout=300 -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories (fallback if no mounted disk)
RUN mkdir -p uploads reports data

# Expose port
EXPOSE 8000

# Health check — longer start period for Render free tier cold starts
HEALTHCHECK --interval=30s --timeout=15s --start-period=60s --retries=5 \
    CMD curl -f http://localhost:${PORT:-8000}/health || exit 1

# Run with uvicorn
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
