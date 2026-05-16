#!/usr/bin/env python3
"""
port-scanner — a fast, concurrent TCP port scanner
"""

import socket
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Common ports and service names
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}

# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def resolve_host(host: str) -> str:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        print(f"{RED}[!] Could not resolve host: {host}{RESET}")
        sys.exit(1)


def scan_port(host: str, port: int, timeout: float) -> dict | None:
    """
    Attempt a TCP connection to host:port.
    Returns a result dict if open, None if closed/filtered.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "unknown")
                # Try to grab a banner
                banner = None
                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                    banner = banner.split("\n")[0][:60]
                except Exception:
                    pass
                return {"port": port, "service": service, "banner": banner}
    except Exception:
        pass
    return None


def parse_ports(port_str: str) -> list[int]:
    """Parse port string like '22,80,100-200' into a list of ints."""
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def print_banner(host: str, ip: str, ports: list[int], timeout: float):
    print(f"\n{BOLD}{CYAN}{'─' * 55}{RESET}")
    print(f"{BOLD}  PORT SCANNER{RESET}")
    print(f"{CYAN}{'─' * 55}{RESET}")
    print(f"  Target   : {BOLD}{host}{RESET} ({ip})")
    print(f"  Ports    : {len(ports)} to scan")
    print(f"  Timeout  : {timeout}s per port")
    print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{CYAN}{'─' * 55}{RESET}\n")


def print_result(result: dict):
    port = result["port"]
    service = result["service"]
    banner = result.get("banner") or ""
    banner_str = f"  {YELLOW}↳ {banner}{RESET}" if banner else ""
    print(f"  {GREEN}[OPEN]{RESET}  {BOLD}{port:>5}/tcp{RESET}  {CYAN}{service:<14}{RESET}{banner_str}")


def scan(host: str, ports: list[int], timeout: float, threads: int) -> list[dict]:
    """Run the scan concurrently and return sorted open port results."""
    open_ports = []
    total = len(ports)
    scanned = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, host, port, timeout): port for port in ports}
        for future in as_completed(futures):
            scanned += 1
            # Progress indicator (overwrite same line)
            print(f"\r  Scanning... {scanned}/{total} ports", end="", flush=True)
            result = future.result()
            if result:
                open_ports.append(result)

    print("\r" + " " * 40 + "\r", end="")  # Clear progress line
    return sorted(open_ports, key=lambda x: x["port"])


def main():
    parser = argparse.ArgumentParser(
        description="A fast concurrent TCP port scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python scanner.py scanme.nmap.org
  python scanner.py 192.168.1.1 -p 22,80,443
  python scanner.py example.com -p 1-1024 --threads 200
  python scanner.py 10.0.0.1 -p common --timeout 0.5
        """,
    )
    parser.add_argument("host", help="Target host (IP or domain)")
    parser.add_argument(
        "-p", "--ports",
        default="common",
        help="Ports to scan: 'common', '80', '1-1024', '22,80,443' (default: common)",
    )
    parser.add_argument(
        "-t", "--threads",
        type=int, default=100,
        help="Number of concurrent threads (default: 100)",
    )
    parser.add_argument(
        "--timeout",
        type=float, default=1.0,
        help="Timeout per port in seconds (default: 1.0)",
    )

    args = parser.parse_args()

    # Resolve ports
    if args.ports == "common":
        ports = sorted(COMMON_PORTS.keys())
    else:
        try:
            ports = parse_ports(args.ports)
        except ValueError:
            print(f"{RED}[!] Invalid port format: {args.ports}{RESET}")
            sys.exit(1)

    if not ports:
        print(f"{RED}[!] No valid ports to scan.{RESET}")
        sys.exit(1)

    ip = resolve_host(args.host)
    print_banner(args.host, ip, ports, args.timeout)

    start = datetime.now()
    results = scan(ip, ports, args.timeout, args.threads)
    elapsed = (datetime.now() - start).total_seconds()

    # Summary
    print(f"{CYAN}{'─' * 55}{RESET}")
    if results:
        print(f"  {GREEN}{BOLD}{len(results)} open port(s) found:{RESET}\n")
        for r in results:
            print_result(r)
    else:
        print(f"  {RED}No open ports found.{RESET}")

    print(f"\n{CYAN}{'─' * 55}{RESET}")
    print(f"  Done in {elapsed:.2f}s  |  {len(ports)} ports scanned")
    print(f"{CYAN}{'─' * 55}{RESET}\n")


if __name__ == "__main__":
    main()
