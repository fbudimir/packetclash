# packetclash - Race Condition Testing Tool

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

### Options (`main.py --help`)

```text
options:
  -h, --help            show this help message and exit
  -f HAR, --har HAR     Path to the HAR file (interactive wizard)
  -u URL, --url URL     Target URL for manual configuration
  -r RAW, --raw RAW     Path to a raw HTTP request file (e.g. from Burp Suite)
  -a {spray,last-byte,single-packet}, --attack {spray,last-byte,single-packet}
                        Attack technique to use (default: spray), ignored when using --har
  -c COUNT, --count COUNT
                        Number of concurrent requests to send (default: 20), ignored when using --har
  --delay DELAY         Delay in ms between spray requests (default: 0), ignored when using --har, only used with --attack spray
  --http2               Use HTTP/2 protocol for spray attack (default: False), ignored when using --har, only used with --attack spray
  --single              Use a single connection (multiplexed/sequential) for spray, ignored when using --har, only used with --attack spray
  --multi               Use multiple isolated connections for spray (default), ignored when using --har, only used with --attack spray
  -X REQUEST, --request REQUEST
                        HTTP Method (default: POST), only used with --url
  -d DATA, --data DATA  Raw request body (e.g., JSON string), only used with --url
  -H HEADER, --header HEADER
                        HTTP headers (e.g., -H 'Authorization: Bearer ...'), only used with --url
  -v, --verbose         Enable verbose library output (default: False), ignored when using --har, only used with --attack single-packet
  -e EXPECTED, --expected EXPECTED
                        Expected number of normal 200 responses (default: 1), ignored when using --har
  --no-tls              Force HTTP (no TLS) (default: https), only used with --raw
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

### Options (`benchmark.py --help`)

```text
options:
  -h, --help            show this help message and exit
  --url URL             Base URL of the target
                        (default: https://127.0.0.1:5003)
  --raceable-route PATH
                        Route to attack with concurrent requests
                        (default: /api/withdraw/rmw)
  --reset-state-route PATH
                        Route called to reset state before each run
                        (default: /api/deposit)
  --check-state-route PATH
                        Route called to check current state
                        (default: /api/balance)
  --reset-state-body JSON
                        Full JSON body sent to the reset-state route
                        (default: '{"amount": 1000}')
  --protocol {http1,http2,both}
                        Which protocol attacks to include:
                          http1: spray, last-byte
                          http2: spray --http2 --single, spray --http2, single-packet
                          both: all of the above
                          (default: both)
  --iterations N, -n N  Number of runs per attack type (default: 50)
  --concurrency N, -c N
                        Concurrent requests per run (default: 50)
```

### Example Usages

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
