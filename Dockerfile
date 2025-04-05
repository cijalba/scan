FROM python:3.13.2-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create necessary directories
RUN mkdir -p reports rules sql_scripts

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python sql_scanner.py --diags

# Run the scanner
ENTRYPOINT ["python", "sql_scanner.py"]
CMD ["-s", "sql_scripts", "-r", "rules", "--report-format", "text", "html", "json", "csv"] 