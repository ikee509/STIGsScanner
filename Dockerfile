FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -r -s /bin/false stig-central

# Create directories
RUN mkdir -p /opt/stig-central /etc/stig-central /var/log/stig-central /var/lib/stig-central

# Set working directory
WORKDIR /opt/stig-central

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY stig_central_server/ .
COPY config.json /etc/stig-central/

# Set permissions
RUN chown -R stig-central:stig-central /opt/stig-central \
    /etc/stig-central \
    /var/log/stig-central \
    /var/lib/stig-central

# Switch to app user
USER stig-central

# Run the application
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000", "--ssl-keyfile", "/etc/stig-central/key.pem", "--ssl-certfile", "/etc/stig-central/cert.pem"] 