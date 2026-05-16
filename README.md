# port-scanner

A fast, concurrent TCP port scanner written in Python. I only used the standard library lol

## Features

- Concurrent scanning with configurable thread count
- Flexible port input: single, range, comma separated, or preset
- Automatic service name detection for common ports
- Basic banner grabbing (HTTP, FTP, SSH, etc)
- Clean, colored CLI output
- Zero external dependencies

## Usage

```bash
# Scan common ports on a host
python scanner.py scanme.nmap.org

# Scan specific ports
python scanner.py 192.168.1.1 -p 22,80,443

# Scan a port range
python scanner.py example.com -p 1-1024

# Crank up threads for speed
python scanner.py 10.0.0.1 -p 1-65535 --threads 500

# Lower timeout for faster scanning (less accurate on slow networks)
python scanner.py example.com --timeout 0.3
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-p`, `--ports` | `common` | Ports to scan: `common`, `80`, `1-1024`, `22,80,443` |
| `-t`, `--threads` | `100` | Number of concurrent threads |
| `--timeout` | `1.0` | Timeout per port (seconds) |

## Example Output

```
───────────────────────────────────────────────────────
  PORT SCANNER
───────────────────────────────────────────────────────
  Target   : scanme.nmap.org (45.33.32.156)
  Ports    : 17 to scan
  Timeout  : 1.0s per port
  Started  : 2024-01-15 14:32:01
───────────────────────────────────────────────────────

───────────────────────────────────────────────────────
  2 open port(s) found:

  [OPEN]     22/tcp  SSH
  [OPEN]     80/tcp  HTTP           ↳ Apache/2.4.7

───────────────────────────────────────────────────────
  Done in 1.24s  |  17 ports scanned
───────────────────────────────────────────────────────
```

## Requirements

- Python 3.10+
- No external packages needed

## ⚠️ Legal Notice

dont do this if u dont have permission, that's not cool bro
## Ideas for Extension

- [ ] UDP scanning
- [ ] OS fingerprinting
- [ ] JSON/CSV output
- [ ] Scan multiple hosts from a file
- [ ] `--verbose` flag for closed ports too
