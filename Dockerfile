FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libopenscap25 \
    openscap-utils \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY scap_prometheus_exporter.py .
COPY scap_exporter.yaml .

# Create directories
RUN mkdir -p /var/log/scap /usr/share/xml/scap/ssg/content

# Download sample SCAP content if not provided
RUN if [ ! -f /usr/share/xml/scap/ssg/content/ssg-debian11-ds.xml ]; then \
    wget -O /usr/share/xml/scap/ssg/content/ssg-debian11-ds.xml \
    https://github.com/ComplianceAsCode/content/releases/latest/download/ssg-debian11-ds.xml || true; \
    fi

# Expose metrics port
EXPOSE 9154

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:9154/health || exit 1

# Run as non-root user
RUN useradd -r -s /bin/false scap && \
    chown -R scap:scap /app /var/log/scap
USER scap

# Default command
CMD ["python3", "scap_prometheus_exporter.py", "--config", "/app/scap_exporter.yaml"]

