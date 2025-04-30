# ArtScan (Linux version 🐧)

ArtScan is a tiny, convenient, and very fast port scanner written in C. It is perfect for pentesting and red team engagements. Its size is only **25 KB**.

![ArtScan](images/ascan.png)

## Features

* IP ranges and port ranges scan with threads and timeout adjustments
* Smart scan of TOP 123 most common ports by default
* Perform ping scan only (skip port scan)
* Grab answers and HTTP responses on opened ports
* Scan summary brief

## Compile
```
gcc -O2 -std=gnu11 -pthread -o scanner scanner.c
```

## Usage

```
Usage: ascan <ip-range> [port-range] [-T threads] [-t timeout_ms] [-r rechecks] [-Pn] [-i] [-h]
  ipRange:   Single IP or range (e.g., 192.168.1.1-100 or 192.168.1.1-192.168.1.100)
  portRange: Single port, range (80-90), or comma-separated list (22,80,443)
  -T:        Set thread limit (default: 100)
  -t:        Set port scan timeout in msec (default: 300)
  -r:        Set extra rechecks for unanswered ports (default: 0)
  -Pn:       Disable ping (skip host availability check)
  -i:        Perform ping scan only (skip port scan)
  -h:        Display this help message

```