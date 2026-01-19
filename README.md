# ArtScan

ArtScan is a multiplatform, tiny, smart, and very fast port scanner written in C. It is perfect for pentesting and red team engagements.

![ArtScan](images/ascan.png)

## Features

* IP ranges and port ranges scan with threads and timeout adjustments
* Fast smart scan of TOP 123 TCP most common ports (by default)
* Fast smart scan of TOP 57 UDP most common ports
* Scan progress
* Perform ping scan only (skip port scan)
* Capture banners and HTTP responses on open ports
* Scan by IP and FQDN
* Netbios hostname resolution
* Brief, sorted scan summary

## Usage

```
Usage: <target> [portRange] [options]
  target:    Hostname (e.g., scanme.nmap.org), single IP, or range (192.168.1.1-100)
  portRange: Single port, range (80-90), comma-separated list (22,80,443), or 'all'
Options:
  -T <num>:  Thread limit (default: 20, max: 50)
  -t <ms>:   Scan timeout in msec (default: 300)
  -r <num>:  Set extra rechecks for unanswered ports (default: 0, max: 10)
  -u:        Perform UDP scan instead of TCP
  -Pn:       Disable ping
  -i:        Ping scan only
  -Nb:       Enable hostname resolution
  -h:        Display this help
```