import json
import sys
from rich.console import Console
from rich.prompt import Prompt, IntPrompt
from models import AttackTarget

console = Console()

KEYWORDS = ["withdraw", "redeem", "purchase", "pay", "checkout", "transfer", "buy"]

def parse_har_interactive(har_path: str):
   

    try:
        with open(har_path, 'r', encoding='utf-8') as f:
            har_data = json.load(f)
    except Exception as e:
        console.print(f"[bold red]Failed to read HAR file:[/bold red] {e}")
        return None

    entries = har_data.get('log', {}).get('entries', [])
    if not entries:
        console.print("[bold red]No entries found in HAR file.[/bold red]")
        return None


    # keyword matching
    matched_requests = []
    seen = set()
    for entry in entries:
        req = entry.get('request', {})
        url = req.get('url', '')
        method = req.get('method', '')
        if any(kw in url.lower() for kw in KEYWORDS):
            key = (method, url)
            if key not in seen:
                seen.add(key)
                matched_requests.append(req)

    if not matched_requests:
        console.print("[bold yellow]No requests matched the predefined keywords.[/bold yellow]")
        # fallback if keywords do not exist
        for entry in entries:
            req = entry.get('request', {})
            url = req.get('url', '')
            method = req.get('method', '')
            if url:
                key = (method, url)
                if key not in seen:
                    seen.add(key)
                    matched_requests.append(req)



    console.print("\n[bold cyan]--- Discovered Potential Targets ---[/bold cyan]")
    for idx, req in enumerate(matched_requests, 1):
        method = req.get('method', 'GET')
        url = req.get('url', '')
        console.print(f"[[bold yellow]{idx}[/bold yellow]] [green]{method}[/green] {url}")

    # choice of url
    choice = IntPrompt.ask("\nSelect a target to attack", choices=[str(i) for i in range(1, len(matched_requests) + 1)], default=1)
    selected_req = matched_requests[choice - 1]

    # default values
    default_url = selected_req.get('url', '')
    default_method = selected_req.get('method', 'POST')
    detected_http_version = selected_req.get('httpVersion', 'HTTP/1.1').upper()
    
    # headers
    default_headers = {}
    for h in selected_req.get('headers', []):
        if h.get('name') and not h['name'].startswith(':'):
            default_headers[h['name']] = h['value']

    # body
    default_body = ""
    post_data = selected_req.get('postData', {})
    if post_data and 'text' in post_data:
        default_body = post_data['text']

    # http version
    console.print(f"\n[*] Detected HTTP Version: [bold]{detected_http_version}[/bold]")
    default_proto_choice = "3"
    if "2" in detected_http_version:
        default_proto_choice = "2"
    elif "1" in detected_http_version:
        default_proto_choice = "1"
        
    proto_choice = Prompt.ask(
        "Which HTTP protocol should be used?\n[1] HTTP/1.1\n[2] HTTP/2\n[3] Both",
        choices=["1", "2", "3"],
        default=default_proto_choice
    )

    # method and body input
    method = Prompt.ask("Request Method", default=default_method)
    
    console.print("\n[*] Discovered Body:")
    console.print(default_body if default_body else "<Empty>")
    body_choice = Prompt.ask("Enter custom body (or press Enter to use discovered)", default=default_body)
    body = body_choice if body_choice else default_body

    target_req = AttackTarget(
        method=method.upper(),
        url=default_url,
        headers=default_headers,
        body=body
    )





    # attack choice and specific parameters for each attack
    attacks_to_run = []
    
    console.print("\n[bold cyan]--- Attack Configuration ---[/bold cyan]")
    
    if proto_choice == "1":
        options = {"1": ("spray", False), "2": ("last-byte", False)}
        prompt_text = "Select HTTP/1.1 attack type:\n[1] Spray\n[2] Last-Byte"
        default_val = "2"
    elif proto_choice == "2":
        options = {"1": ("spray", True), "2": ("single-packet", True)}
        prompt_text = "Select HTTP/2 attack type:\n[1] Spray\n[2] Single-Packet Attack (SPA)"
        default_val = "2"
    else:
        options = {
            "1": ("spray", False), 
            "2": ("last-byte", False), 
            "3": ("spray", True), 
            "4": ("single-packet", True)
        }
        prompt_text = "Select an attack type to run:\n[1] Spray (HTTP/1.1)\n[2] Last-Byte (HTTP/1.1)\n[3] Spray (HTTP/2)\n[4] Single-Packet Attack (SPA) (HTTP/2)"
        default_val = "4"

    if proto_choice == "3":
        choices_str = Prompt.ask(prompt_text, choices=["1", "2", "3", "4"], default=default_val)
    else:
        choices_str = Prompt.ask(prompt_text, choices=["1", "2"], default=default_val)
        
    selected_keys = [choices_str]
    
    for key in selected_keys:
        att_type, is_h2 = options[key]
        if att_type == "spray":
            mode = Prompt.ask(f"Connection Mode for Spray ({'HTTP/2' if is_h2 else 'HTTP/1.1'}):\n[1] Multi (Isolated/Concurrent)\n[2] Single (Multiplexed/Sequential)", choices=["1", "2"], default="1")
            attacks_to_run.append({"type": "spray", "http2": is_h2, "multi": (mode == "1")})
        elif att_type == "last-byte":
            attacks_to_run.append({"type": "last-byte", "http2": False})
        elif att_type == "single-packet":
            verbose_prompt = Prompt.ask("Enable verbose output for SPA?", choices=["y", "n"], default="n")
            attacks_to_run.append({"type": "single-packet", "verbose": (verbose_prompt == "y"), "http2": True})

    # global options
    console.print("\n[bold cyan]--- Global Options ---[/bold cyan]")
    count = IntPrompt.ask("Number of concurrent requests", default=50)
    
    delay = 0
    if any(a["type"] == "spray" for a in attacks_to_run):
        delay = IntPrompt.ask("Stagger delay (ms) for spray attacks", default=0)
        
    expected = IntPrompt.ask("Expected number of normal 200 responses (baseline)", default=1)

    return {
        "target": target_req,
        "attacks": attacks_to_run,
        "count": count,
        "delay": delay,
        "expected": expected
    }
