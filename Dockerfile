FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app/ app/
COPY test_detector.py .

# Expose API port
EXPOSE 8000

# Default command: run API
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
