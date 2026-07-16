import argparse
import sys
import signal

def sigint_handler(sig, frame):
    print("\nAborted by user (Ctrl+C)")
    sys.exit(1)

signal.signal(signal.SIGINT, sigint_handler)
from rich.console import Console
from models import AttackTarget
from engine import run_spray, last_byte_sync_attack, single_packet_attack
from har_parser import parse_har_interactive
from raw_parser import parse_raw_request

# rich console init
console = Console()

def parse_manual_headers(header_list):

    headers = {}
    if not header_list:
        return headers
    for h in header_list:
        if ':' in h:
            key, value = h.split(':', 1)
            headers[key.strip()] = value.strip()
    return headers

def main():
    parser = argparse.ArgumentParser(description="PacketClash - Race Condition Testing Tool")
    
    # mutually exclusive pocetni odabir nacina rada
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("-f", "--har", help="Path to the HAR file (interactive wizard)")
    input_group.add_argument("-u", "--url", help="Target URL for manual configuration")
    input_group.add_argument("-r", "--raw", help="Path to a raw HTTP request file (e.g. from Burp Suite)")

    # attack choice and number of requests
    parser.add_argument("-a", "--attack", choices=['spray', 'last-byte', 'single-packet'], 
                        default='spray', help="Attack technique to use (default: spray), ignored when using --har")
    parser.add_argument("-c", "--count", type=int, default=50, 
                        help="Number of concurrent requests to send (default: 50), ignored when using --har")

    # SPRAY ONLY
    # delay and protocol choice
    parser.add_argument("--delay", type=int, default=0, 
                        help="Delay in ms between spray requests (default: 0), ignored when using --har, only used with --attack spray")
    parser.add_argument("--http2", action="store_true",
                        help="Use HTTP/2 protocol for spray attack (default: False), ignored when using --har, only used with --attack spray")
    # connection mode
    conn_group = parser.add_mutually_exclusive_group()
    conn_group.add_argument("--single", action="store_true", help="Use a single connection (multiplexed/sequential) for spray, ignored when using --har, only used with --attack spray")
    conn_group.add_argument("--multi", action="store_true", help="Use multiple isolated connections for spray (default), ignored when using --har, only used with --attack spray")
    

    # misc options
    parser.add_argument("-X", "--request", default="POST", help="HTTP Method (default: POST), only used with --url")
    parser.add_argument("-d", "--data", help="Raw request body (e.g., JSON string), only used with --url")
    parser.add_argument("-H", "--header", action="append", 
                        help="HTTP headers (e.g., -H 'Authorization: Bearer ...'), only used with --url")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose library output (default: False), ignored when using --har, only used with --attack single-packet")
    parser.add_argument("-e", "--expected", type=int, default=1,
                        help="Expected number of normal 200 responses (default: 1), ignored when using --har")
    parser.add_argument("--no-tls", action="store_true",
                        help="Force HTTP (no TLS) (default: False), only used with --raw")

    args = parser.parse_args()



    # welcome
    console.print(f"[bold cyan]PacketClash v0.1[/bold cyan]")
    if args.har:
        console.print(f"[*] Mode: [bold yellow]HAR Discovery (Interactive)[/bold yellow]\n")
    elif args.raw:
        console.print(f"[*] Mode: [bold yellow]{args.attack.upper()}[/bold yellow] | Raw Request File | {args.count} requests\n")
    else:
        console.print(f"[*] Mode: [bold yellow]{args.attack.upper()}[/bold yellow] | Manual URL | {args.count} requests\n")



    # target discovery
    # --har
    if args.har:
        console.print(f"[*] Parsing HAR file: [green]{args.har}[/green]")
        try:
            config = parse_har_interactive(args.har)
            if not config:
                sys.exit(1)
        except KeyboardInterrupt:
            console.print("\n[bold red]Wizard aborted by user (Ctrl+C)[/bold red]")
            sys.exit(1)
            
        target_req = config["target"]
        try:
            for attack_cfg in config["attacks"]:
                console.print(f"\n[bold magenta]=== Executing Attack: {attack_cfg['type'].upper()} ===[/bold magenta]")
                if attack_cfg['type'] == 'spray':
                    run_spray(target_req, config["count"], config["delay"], attack_cfg["http2"], attack_cfg.get("multi", True), config["expected"])
                elif attack_cfg['type'] == 'last-byte':
                    last_byte_sync_attack(target_req, config["count"], config["expected"])
                elif attack_cfg['type'] == 'single-packet':
                    single_packet_attack(target_req, config["count"], attack_cfg.get("verbose", False), config["expected"])
            
            console.print("\n[bold green]Interactive Attacks completed![/bold green]")
        except KeyboardInterrupt:
            console.print("\n[bold red]Attack aborted by user (Ctrl+C)[/bold red]")
            sys.exit(1)
        except Exception as e:
            console.print(f"\n[bold red]FATAL ERROR:[/bold red] {e}")
            sys.exit(1)
            
        return 
    
    # --raw
    elif args.raw:
        console.print(f"[*] Loading raw request file: [green]{args.raw}[/green]")
        target_req = parse_raw_request(args.raw)
        if args.no_tls:
            # override scheme
            target_req = target_req.__class__(
                method=target_req.method,
                url=target_req.url.replace('https://', 'http://', 1),
                headers=target_req.headers,
                body=target_req.body
            )
    # --url
    else:
        console.print(f"[*] Using manual target: [green]{args.url}[/green]")
        headers = parse_manual_headers(args.header)
        target_req = AttackTarget(
            method=args.request.upper(),
            url=args.url,
            headers=headers,
            body=args.data
        )

    console.print(f"[+] Target loaded: [bold]{target_req.method} {target_req.path}[/bold]")



    # execution
    if args.attack == 'spray':
        console.print("[*] Launching Spray attack...")
        is_multi = not args.single
        run_spray(target_req, args.count, args.delay, args.http2, is_multi, args.expected)
    elif args.attack == 'last-byte':
        console.print("[*] Launching Last-Byte Sync attack...")
        last_byte_sync_attack(target_req, args.count, args.expected)
    elif args.attack == 'single-packet':
        console.print("[*] Launching HTTP/2 Single-Packet attack...")
        single_packet_attack(target_req, args.count, args.verbose, args.expected)
        
    console.print("\n[bold green]Attack completed![/bold green]")




if __name__ == "__main__":
    main()