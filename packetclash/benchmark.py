import subprocess
import re
import time
import statistics
import argparse
import json
import httpx
import urllib3
import os
import csv
from datetime import datetime

# ignore self-signed certs warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# defaults
DEFAULT_URL               = "https://127.0.0.1:5003" # Local
# DEFAULT_URL               = "https://X.X.X.X:5003" # Public Far
# DEFAULT_URL               = "https://X.X.X.X:5003" # Public Close


DEFAULT_RACEABLE_ROUTE    = "/api/withdraw/rmw"
DEFAULT_RESET_STATE_ROUTE = "/api/deposit"
DEFAULT_CHECK_STATE_ROUTE = "/api/balance"
DEFAULT_RESET_STATE_BODY  = '{"amount": 1000}'
DEFAULT_PROTOCOL          = "both"   # "http1", "http2", or "both"
DEFAULT_ITERATIONS        = 3
DEFAULT_CONCURRENCY       = 50


def parse_args():
    parser = argparse.ArgumentParser(
        description="PacketClash Benchmark — Race Condition Attack Benchmarker",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_URL,
        metavar="URL",
        help=f"Base URL of the target\n(default: {DEFAULT_URL})"
    )
    parser.add_argument(
        "--raceable-route",
        default=DEFAULT_RACEABLE_ROUTE,
        metavar="PATH",
        help=f"Route to attack with concurrent requests\n(default: {DEFAULT_RACEABLE_ROUTE})"
    )
    parser.add_argument(
        "--reset-state-route",
        default=DEFAULT_RESET_STATE_ROUTE,
        metavar="PATH",
        help=f"Route called to reset state before each run\n(default: {DEFAULT_RESET_STATE_ROUTE})"
    )
    parser.add_argument(
        "--check-state-route",
        default=DEFAULT_CHECK_STATE_ROUTE,
        metavar="PATH",
        help=f"Route called to check current state\n(default: {DEFAULT_CHECK_STATE_ROUTE})"
    )
    parser.add_argument(
        "--reset-state-body",
        default=DEFAULT_RESET_STATE_BODY,
        metavar="JSON",
        help=f"Full JSON body sent to the reset-state route\n(default: '{DEFAULT_RESET_STATE_BODY}')"
    )
    parser.add_argument(
        "--protocol",
        choices=["http1", "http2", "both"],
        default=DEFAULT_PROTOCOL,
        help=(
            "Which protocol attacks to include:\n"
            "  http1: spray, last-byte\n"
            "  http2: spray --http2 --single, spray --http2, single-packet\n"
            "  both: all of the above\n"
            f"  (default: {DEFAULT_PROTOCOL})"
        )
    )
    parser.add_argument(
        "--iterations", "-n",
        type=int,
        default=DEFAULT_ITERATIONS,
        metavar="N",
        help=f"Number of runs per attack type (default: {DEFAULT_ITERATIONS})"
    )
    parser.add_argument(
        "--concurrency", "-c",
        type=int,
        default=DEFAULT_CONCURRENCY,
        metavar="N",
        help=f"Concurrent requests per run (default: {DEFAULT_CONCURRENCY})"
    )
    return parser.parse_args()
    return parser.parse_args()


def build_attacks(protocol):
    if protocol == "http1":
        return ["spray", "last-byte"]
    elif protocol == "http2":
        return ["spray --http2 --single", "spray --http2", "single-packet"]
    else:
        return ["spray", "spray --http2 --single", "spray --http2", "last-byte", "single-packet"]







def run_benchmark(args):
    base_url         = args.url.rstrip("/")
    raceable_url     = base_url + args.raceable_route
    reset_state_url  = base_url + args.reset_state_route
    check_state_url  = base_url + args.check_state_route
    reset_body_json  = json.loads(args.reset_state_body)

    iterations       = args.iterations
    concurrency      = args.concurrency
    attacks          = build_attacks(args.protocol)

    final_report = {}





    print(f"\n Target: {base_url} | Protocol: {args.protocol.upper()} | Concurrency: {concurrency} | Iterations: {iterations}")

    for attack in attacks:
        print(f"\n[!] Starting {iterations} runs for: {attack.upper()}")
        results = []

        for i in range(1, iterations + 1):
            # reset state
            try:
                with httpx.Client(verify=False, http2=True, timeout=10.0) as client:
                    state_resp = client.get(check_state_url)

                    ########################################################################
                    time.sleep(0.2) # necessary for packet and request rate limiting
                    ########################################################################

                    state_data = state_resp.json()
                    # parsing numbers, experimental, specific use-case
                    current = next((float(v) for v in state_data.values() if isinstance(v, (int, float))), None)
                    needed  = next((float(v) for v in reset_body_json.values() if isinstance(v, (int, float))), None)
                    if current is None or needed is None or current < needed:
                        top_up = (needed - current) if (current is not None and needed is not None) else (needed or 0)
                        top_up_body = {k: (top_up if isinstance(v, (int, float)) else v) for k, v in reset_body_json.items()}
                        client.post(reset_state_url, json=top_up_body)
                        time.sleep(1)
            except Exception as e:
                print(f"  Run {i}/{iterations}: State reset failed! {e}")
                continue

            # start attack
            attack_parts = attack.split()
            base_attack  = attack_parts[0]
            extra_args   = attack_parts[1:]

            cmd = [
                "python3", "main.py",
                "-u", raceable_url,
                "-X", "POST",
                "-d", args.reset_state_body,
                "-H", "Content-Type: application/json",
                "-a", base_attack,
                "-c", str(concurrency)
            ]
            cmd.extend(extra_args)

            try:
                output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
                match  = re.search(r"200 OK: (\d+) times", output)
                if match:
                    count = int(match.group(1))
                    results.append(count)
                    print(f"  Run {i}/{iterations}: {count} hits              ", end="\r")
                else:
                    results.append(0)
                    print(f"  Run {i}/{iterations}: 0 hits (error?)       ", end="\r")
            except Exception as e:
                print(f"  Run {i}/{iterations}: Failed! {str(e)}")

            time.sleep(0.3)






        if results:
            final_report[attack] = {
                "avg":     round(statistics.mean(results), 1),
                "max":     max(results),
                "min":     min(results),
                "std_dev": round(statistics.stdev(results), 2) if len(results) > 1 else 0.0
            }

    display_names = {
        "spray": "HTTP/1.1 MC Spray",
        "spray --http2 --single": "HTTP/2 SC Spray",
        "spray --http2": "HTTP/2 MC Spray",
        "last-byte": "Last-Byte",
        "single-packet": "Single-Packet"
    }






    # CLI output table
    print("\n\n" + "=" * 70)
    print(f"{'Attack Type':<25} | {'Avg Hits':<10} | {'Max':<6} | {'Min':<6} | {'StdDev':<6}")
    print("-" * 70)
    for attack, stats in final_report.items():
        display_name = display_names.get(attack, attack)
        print(f"{display_name:<25} | {stats['avg']:<10} | {stats['max']:<6} | {stats['min']:<6} | {stats['std_dev']:<6}")
    print("=" * 70)





    # export to csv
    try:
        os.makedirs("benchmark_data", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"benchmark_data/results_{timestamp}.csv"
        
        with open(filename, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Attack Type", "Avg Hits", "Max", "Min", "StdDev"])
            for attack, stats in final_report.items():
                display_name = display_names.get(attack, attack)
                writer.writerow([display_name, stats['avg'], stats['max'], stats['min'], stats['std_dev']])
                
        print(f"\n[+] Results successfully exported to: {filename}")
    except Exception as e:
        print(f"\n[!] Failed to export to CSV: {e}")


if __name__ == "__main__":
    run_benchmark(parse_args())