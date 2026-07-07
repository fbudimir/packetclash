import asyncio
import httpx
import time
from collections import Counter
from rich.console import Console
from models import AttackTarget
import socket
import ssl
import time
import threading
from h2spacex import H2OnTlsConnection
from h2spacex import logger as h2_logger
import re


console = Console()



# pretty analysis and output
def print_analysis_and_reporting(duration, results, expected_successes: int = 1):

    console.print(f"\n[bold green]Attack completed in {duration:.4f} seconds![/bold green]")
    
    status_counts = Counter(results)
    
    console.print("\n[bold]Results (Status Codes):[/bold]")
    for status, freq in status_counts.items():
        if status == 200:
            console.print(f"  - [green]200 OK[/green]: {freq} times")
        elif isinstance(status, int) and status >= 400:
            rate_limit_msg = " [red](Possible rate limiting)[/red]" if status in (429, 503) else ""
            console.print(f"  - [red]{status}[/red]: {freq} times" + rate_limit_msg)
        else:
            console.print(f"  - [yellow]{status}[/yellow]: {freq} times")
            
    if status_counts.get(200, 0) > expected_successes:
        console.print("\n[bold red]POSSIBLE RACE CONDITION DETECTED![/bold red]")
        console.print(f"    Received {status_counts.get(200, 0)} OK responses (expected at most {expected_successes}).")






# for --har and --raw to not duplicate headers in httpx
HTTPX_FORBIDDEN_HEADERS = {'content-length', 'transfer-encoding', 'connection', 'keep-alive', 'upgrade', 'proxy-connection'}

# sends a single asynchronous HTTP request and returns the status code
async def send_request(client: httpx.AsyncClient, target: AttackTarget, req_id: int):
    try:
        safe_headers = {k: v for k, v in target.headers.items() if k.lower() not in HTTPX_FORBIDDEN_HEADERS}
        response = await client.request(
            method=target.method,
            url=target.url,
            headers=safe_headers,
            content=target.body,
            timeout=10.0
        )
        return response.status_code
    except Exception as e:
        return f"Error: {type(e).__name__}"

# sends a single asynchronous HTTP request using its OWN isolated client
async def send_isolated_request(target: AttackTarget, req_id: int, http2: bool):
 
    async with httpx.AsyncClient(verify=False, http2=http2) as client:
        return await send_request(client, target, req_id)





# SPRAY -----------------------
async def execute_spray(target: AttackTarget, count: int, delay_ms: int = 0, http2: bool = False, multi_conn: bool = True, expected_successes: int = 1):
 
    console.print("[bold yellow][!] Using SPRAY method[/bold yellow]")

    results = []
    
    if delay_ms > 0:
        console.print(f"[*] Preparing {count} requests with a {delay_ms}ms delay...")
    else:
        console.print(f"[*] Preparing {count} requests...")
        
    if http2:
        if multi_conn:
            console.print("[*] Using HTTP/2 protocol (Multi-Connection mode)")
        else:
            console.print("[*] Using HTTP/2 protocol (Single-Connection Multiplexing)")
    else:
        if multi_conn:
            console.print("[*] Using HTTP/1.1 protocol (Multi-Connection mode)")
        else:
            console.print("[*] Using HTTP/1.1 protocol (Single-Connection mode)")
            console.print("[bold yellow][*] --- WARNING: HTTP/1.1 single-connection is sequential, requests should not race[/bold yellow]")
        


    console.print("[bold yellow][!] Starting attack...[/bold yellow]")
    start_time = time.time()
    
    if multi_conn:
        tasks = []
        for i in range(count):
            task = asyncio.create_task(send_isolated_request(target, i, http2))
            tasks.append(task)
            if delay_ms > 0:
                await asyncio.sleep(delay_ms / 1000.0)
        results = await asyncio.gather(*tasks)
    else:
        # if http2, multiplexes all requests over 1 TCP connection.
        limits = httpx.Limits(max_connections=1, max_keepalive_connections=1)
        async with httpx.AsyncClient(limits=limits, verify=False, http2=http2) as client:
            # warm up the connection to establish TCP handshake and maybe expand initcwnd, experimental
            try:
                base_url = "/".join(target.url.split("/")[:3]) # extract scheme://host:port
                await client.get(base_url, timeout=5.0)

                ########################################################################
                time.sleep(0.2) # necessary for packet and request rate limiting
                ########################################################################

            except Exception:
                pass # ignore warmup errors
            
            tasks = []
            for i in range(count):
                task = asyncio.create_task(send_request(client, target, i))
                tasks.append(task)
                if delay_ms > 0:
                    await asyncio.sleep(delay_ms / 1000.0)
            results = await asyncio.gather(*tasks)
    
    end_time = time.time()
    duration = end_time - start_time



    # analysis and reporting
    print_analysis_and_reporting(duration, results, expected_successes)



def run_spray(target: AttackTarget, count: int, delay_ms: int = 0, http2: bool = False, multi_conn: bool = True, expected_successes: int = 1):
    # wrapper to start the asyncio event loop.
    asyncio.run(execute_spray(target, count, delay_ms, http2, multi_conn, expected_successes))









# LAST BYTE -----------------------------------

def prepare_http1_request(target):
    # building a basic HTTP1.1 POST request
    request = f"POST {target.path} HTTP/1.1\r\n"
    request += f"Host: {target.host}\r\n"
    
    # checking if content-type is already in headers
    has_content_type = any(k.lower() == 'content-type' for k in target.headers.keys())
    if not has_content_type:
        request += "Content-Type: application/json\r\n"
        
    for k, v in target.headers.items():
        if k.lower() == "host" or k.lower() == "content-length" or k.lower() == "connection":
            continue
        request += f"{k}: {v}\r\n"
    
    body = target.body if target.body else "{}"
    request += f"Content-Length: {len(body)}\r\n"
    request += "Connection: keep-alive\r\n"
    request += "\r\n"
    request += body
    return request.encode()

def last_byte_sync_attack(target, count, expected_successes: int = 1):

    console.print("[bold yellow][!] Using LAST-BYTE method[/bold yellow]")


    raw_request = prepare_http1_request(target)
    head = raw_request[:-1]
    last_byte = raw_request[-1:]
    
    sockets = []
    use_tls = target.url.startswith("https")
    if use_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE




    console.print(f"[*] Opening {count} connections and sending partial data to {target.hostname}:{target.port}...")
    
    try:
        for i in range(count):
            try:
                sock = socket.create_connection((target.hostname, target.port), timeout=5.0)
                if use_tls:
                    sock = context.wrap_socket(sock, server_hostname=target.hostname)
                # send all except last
                sock.sendall(head)
                sockets.append(sock)

            # failsafe for if any connection fails
            except ConnectionRefusedError:
                console.print(f"[bold red][!] Connection {i+1} refused! Stopping at {len(sockets)} connections.[/bold red]")
                break
            except Exception as e:
                console.print(f"[bold red][!] Connection {i+1} failed ({type(e).__name__}). Stopping at {len(sockets)} connections.[/bold red]")
                break
                
        if not sockets:
            console.print("[bold red][!] Failed to establish any connections. Attack aborted.[/bold red]")
            return

        console.print(f"[*] {len(sockets)} connections ready. Synchronizing last byte...")
        
        # small delay for server buffers to be ready
        time.sleep(1)

        # sending the final bytes
        console.print("[bold yellow][!] Starting attack...[/bold yellow]")
        start_time = time.time()
        for s in sockets:
            s.sendall(last_byte)

        end_time = time.time()
        duration = end_time - start_time




        # collect responses
        results = []
        for i, s in enumerate(sockets):
            s.settimeout(2.0)
            try:
                response = s.recv(4096)
                if response:
                    # extract HTTP status code from the first line
                    first_line = response.split(b'\r\n')[0]
                    parts = first_line.split(b' ', 2)
                    if len(parts) >= 2:
                        status_code = int(parts[1])
                        results.append(status_code)
                    else:
                        results.append("Malformed HTTP Response")
                else:
                    results.append("Empty Response")

            except socket.timeout:
                results.append("TIMEOUT")
            except Exception as e:
                results.append(f"Error: {type(e).__name__}")
        
        
        # analysis and reporting
        print_analysis_and_reporting(duration, results, expected_successes)

    finally:
        for s in sockets:
            try:
                s.close()
            except Exception:
                pass








# SINGLE PACKET --------------------

# SPA with h2spacex API
def single_packet_attack(target, count, verbose=False, expected_successes: int = 1):


    console.print("[bold yellow][!] Using SINGLE-PACKET method[/bold yellow]")

    # h2spacex logger silent by default, verbose when -v
    h2_logger.be_silent_key = not verbose
    h2_logger.debug = verbose




    h2_conn = H2OnTlsConnection(
        hostname=target.hostname,
        port_number=target.port
    )

    console.print(f"[*] Establishing TLS connection to {target.hostname}:{target.port}...")
    h2_conn.setup_connection()

    # building headers string in h2spacex format: "key: value\nkey2: value2"
    # excluding pseudo-headers (:method, :path, etc.)
    has_content_type = False
    header_lines = []
    for k, v in target.headers.items():
        if k.startswith(':'):
            continue
        if k.lower() == 'content-type':
            has_content_type = True
        if k.lower() == 'host' or k.lower() == 'content-length' or k.lower() == 'connection':
            continue
        header_lines.append(f"{k.lower()}: {v}")
        
    if not has_content_type:
        header_lines.append("content-type: application/json")
        
    extra_headers_lines = "\n".join(header_lines)

    body = target.body or "{}"


    # client-initiated streams use odd number IDs, starting from 1
    stream_ids = [i*2 + 1 for i in range(count)]

    console.print(f"[*] Pre-calculating binary frames for {count} requests...")
    all_partial = b""
    all_triggers = b""

    for s_id in stream_ids:
        partial, trigger = h2_conn.create_single_packet_http2_post_request_frames(
            authority=target.hostname,
            scheme=target.scheme,
            path=target.path,
            headers_string=extra_headers_lines,
            stream_id=s_id,
            body=body,
            method=target.method,
        )
        all_partial += bytes(partial)
        all_triggers += bytes(trigger)





    # send partial frames (headers + body-minus-last-byte) for all streams
    console.print("[bold yellow][!] Sending headers/partial data...[/bold yellow]")
    h2_conn.send_frames(all_partial)

    # ping warms up connection so the server is ready (h2spacex version)
    h2_conn.send_ping_frame()
    time.sleep(0.1)

    # fire all last bytes in one write, "single packet"
    console.print("[bold yellow][!] FIRING TRIGGER PACKET...[/bold yellow]")
    start_time = time.time()
    h2_conn.send_frames(all_triggers)

    # collect responses
    console.print("[*] Waiting for responses...")
    h2_conn.start_thread_response_parsing(_timeout=5)

    while not h2_conn.is_threaded_response_finished:
        time.sleep(0.5)

    duration = time.time() - start_time





    # headers_and_data_frames[stream_id]['header'] has following format:
    # ":status 200\ncontent-type: application/json\n..."
    results = []
    frame_parser = h2_conn.threaded_frame_parser
    if frame_parser:
        for stream_id, d in frame_parser.headers_and_data_frames.items():
            header_str = d.get('header', '')
            match = re.search(r':status\s+(\d+)', header_str)
            if match:
                results.append(int(match.group(1)))
            else:
                results.append("No Status")
    else:
        results = ["No Response"] * count

    h2_conn.close_connection()





    # analysis and reporting
    print_analysis_and_reporting(duration, results, expected_successes)


    