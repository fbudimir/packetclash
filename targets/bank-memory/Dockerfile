FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir gunicorn gevent

COPY . .

CMD ["gunicorn", "-w", "1", "-k", "gevent", "--capture-output", "-b", "0.0.0.0:5002", "app:app"]