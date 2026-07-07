# DIPL_RAD

This repository contains the source code for the `packetclash` tool and several test web applications (`targets`) developed for analyzing and exploiting race conditions.

## Project Structure

```text
DIPL_RAD/
├── packetclash/        # The race condition testing tool
│   ├── main.py         # Main entry point for the tool
│   ├── benchmark.py    # Script for running comparative analysis
│   └── ...
└── targets/            # Vulnerable target applications
    ├── bank/           # Flask app with PostgreSQL
    ├── bank-memory/    # Flask app with Redis
    ├── bank-node/      # Node.js app with PostgreSQL
    └── docker-compose.yml
```

## Running Target Applications

The test applications run in Docker containers. Ensure you have Docker and Docker Compose installed.

1. Navigate to the `targets` directory:
   ```bash
   cd targets
   ```
2. Generate a certificate and key for HTTPS communication:
   ```bash
   openssl req -x509 -newkey rsa:2048 -keyout certs/server.key -out certs/server.crt -days 365 -nodes
   ```
3. Build and start the containers:
   ```bash
   docker compose up
   ```

The applications will be available at:
- **Flask (PostgreSQL):** `https://localhost:5000`
- **Flask (Redis):** `https://localhost:5002`
- **Node.js (PostgreSQL):** `https://localhost:5003`

## Installing and Running `packetclash`

The tool requires Python 3.12.7+ and a virtual environment.

1. Navigate to the `packetclash` directory:
   ```bash
   cd packetclash
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Example Usages

**Manual configuration (URL):**
```bash
python main.py --url https://localhost:5000/api/withdraw/rmw -X POST -d '{"amount": 1000}' -H 'Content-Type: application/json' -a spray --http2 -c 50
```

**Using a raw request file:**
```bash
python main.py --raw /path/to/request.txt -a spray --http2 -c 50
```

**Using a HAR file:**
```bash
python main.py --har /path/to/file.har
```

## Running the Benchmark Analysis

To run a comparative benchmark analysis across different protocols and attack types, use the `benchmark.py` script while inside the active `packetclash` virtual environment.

Example usage:
```bash
python benchmark.py \
  --url https://localhost:5003 \
  --raceable-route /api/withdraw/rmw \
  --reset-state-route /api/deposit \
  --check-state-route /api/balance \
  --reset-state-body '{"amount": 1000}' \
  --protocol both \
  --iterations 50 \
  --concurrency 50
```
