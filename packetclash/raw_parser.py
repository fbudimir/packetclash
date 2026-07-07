import sys
from models import AttackTarget
from urllib.parse import urlparse


def parse_raw_request(path: str) -> AttackTarget:
    

    try:
        with open(path, 'r', encoding='utf-8') as f:
            raw = f.read()
    except Exception as e:
        print(f"[!] Failed to read request file: {e}")
        sys.exit(1)

    # split into header block and optional body
    # empty line is the separator
    lines = raw.splitlines()
    header_lines = []
    body_lines = []
    in_body = False
    
    for line in lines:
        if not in_body and line.strip() == "":
            in_body = True
            continue
        if in_body:
            body_lines.append(line)
        else:
            header_lines.append(line)

    if not header_lines:
        print("[!] Request file is empty.")
        sys.exit(1)

    # parse the request line, eg. METHOD /path HTTP/1.1
    request_line = header_lines[0].strip()
    parts = request_line.split(' ', 2)
    if len(parts) < 2:
        print(f"[!] Malformed request line: {request_line!r}")
        sys.exit(1)

    method = parts[0].upper()
    raw_path = parts[1]

    scheme = 'https'
    if raw_path.lower().startswith(('http://', 'https://')):
        parsed = urlparse(raw_path)
        scheme = parsed.scheme
        path = parsed.path if parsed.path else '/'
        if parsed.query:
            path += f"?{parsed.query}"
    else:
        path = raw_path

    # parse headers
    headers = {}
    for line in header_lines[1:]:
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip()] = v.strip()

    # reconstruct URL from Host header
    host_header = headers.get('Host') or headers.get('host')
    if not host_header:
        print("[!] No 'Host:' header found in request file. Cannot determine target URL.")
        sys.exit(1)

    url = f"{scheme}://{host_header}{path}"

    body = "\n".join(body_lines).strip()
    if not body:
        body = None

    return AttackTarget(
        method=method,
        url=url,
        headers=headers,
        body=body
    )
