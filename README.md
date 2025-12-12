[![](https://github.com/demyanovs/loginspector/actions/workflows/go.yml/badge.svg)](https://github.com/demyanovs/loginspector/actions) [![Go Reference](https://pkg.go.dev/badge/github.com/demyanovs/loginspector.svg)](https://pkg.go.dev/github.com/demyanovs/loginspector)

# LogInspector

Fast and powerful web server access log inspector.

## Features

- Fast parsing of large log files (buffered I/O)
- Comprehensive statistics (IPs, browsers, devices, OS, bots, etc.)
- Flexible filtering (time ranges, IPs, status codes, etc.)
- Advanced bot detection
- Time distribution analysis
- Suspicious IP detection (high error rates, 403s)
- Handles multi-GB log files efficiently

## Installation

### Download Binary
Download pre-built binaries from [Releases](https://github.com/demyanovs/loginspector/releases):

```bash
# Linux/macOS
curl -L https://github.com/demyanovs/loginspector/releases/latest/download/loginspector-linux-amd64 -o loginspector
chmod +x loginspector

# Or download from browser and extract
```

### Using go install
```bash
go install github.com/demyanovs/loginspector@latest
```

### From source
```bash
git clone https://github.com/demyanovs/loginspector.git
cd loginspector
go build -o loginspector
```

## Quick Start

```bash
# Analyze all sections
loginspector access.log

# Show only specific sections
loginspector -bots -ips access.log

# Custom limits
loginspector -limit=50 access.log

# Filter by time range
loginspector -from="08/Dec/2025:08:00:00" -to="08/Dec/2025:18:00:00" access.log

# Filter by status codes
loginspector -status-code="4xx,5xx" access.log    # Only errors
loginspector -exclude-status="2xx" access.log      # Except success
```

## Usage

```
Usage: loginspector [flags] access.log

Analyze web server access logs and display statistics

Sections (without flags all sections shown, with flags only specified ones):
  -ips        Top IPs - IP addresses with most requests (bots are marked)
  -status     HTTP Status Codes - Server response distribution
  -browser    Browser Statistics - Browser usage (Chrome, Firefox, Safari, etc.)
  -device     Device Statistics - Desktop, Mobile, Tablet distribution
  -os         OS Statistics - Operating system distribution
  -paths      Paths - Most requested URLs on your site
  -time       Time Distribution - Request activity by hour
  -bots       Bots - Identified bot/crawler traffic breakdown
  -suspicious Suspicious IPs - IPs with high error rates
  -requests   Requests - Detailed log entries (all fields)

Filters (apply to all sections and statistics):
  -from             Filter logs from this time (format: 08/Dec/2025:08:30:00)
  -to               Filter logs until this time (format: 08/Dec/2025:18:30:00)
  -status-code      Include only these status codes (comma-separated, ranges: 2xx,3xx,4xx,5xx)
  -exclude-status   Exclude these status codes (comma-separated, ranges: 2xx,3xx,4xx,5xx)
  -bot              Filter by bot name(s) - comma-separated for multiple (e.g., "Googlebot,YandexBot")
  -exclude-bot      Exclude bot name(s) - comma-separated for multiple (e.g., "Googlebot,YandexBot")
  -method           Filter by HTTP method(s) - comma-separated for multiple (e.g., "GET,POST")
  -exclude-method   Exclude HTTP method(s) - comma-separated for multiple (e.g., "HEAD,OPTIONS")
  -ip               Filter by IP address(es) - comma-separated for multiple (e.g., "192.168.1.1,10.0.0.1")
  -exclude-ip       Exclude IP address(es) - comma-separated for multiple (e.g., "127.0.0.1,::1")
  -user-agent       Filter by user-agent(s) - comma-separated for multiple (exact match)
  -exclude-user-agent Exclude user-agent(s) - comma-separated for multiple (exact match)
  -domain           Filter by domain - exact match (e.g., "www.example.com")

Other flags:
  -limit int      Override default limits (IPs:10, Status:10, Paths:10, Bots:10)

Examples:
  loginspector access.log              # Show all sections
  loginspector -requests -from="08/Dec/2025:08:00:00" -to="08/Dec/2025:18:00:00" access.log # Show detailed requests in time range
  loginspector -bots access.log        # Show only bots
  loginspector -bots -ips access.log   # Show only bots and IPs
  loginspector -bots -limit=50 access.log
  loginspector -from="07/Dec/2025:12:00:00" access.log  # From specific time onwards
  loginspector -status-code="200" access.log             # Only 200 OK responses
  loginspector -status-code="4xx,5xx" access.log        # Only errors
  loginspector -exclude-status="2xx" access.log         # All except success
  loginspector -from="..." -status-code="5xx" access.log  # Combine filters
  loginspector -bot="Googlebot" access.log                 # Only Googlebot traffic
  loginspector -exclude-bot="Googlebot,YandexBot" access.log  # Exclude specific bots
  loginspector -method="GET,POST" access.log               # Only GET and POST
  loginspector -exclude-method="HEAD,OPTIONS" access.log   # Exclude HEAD and OPTIONS
  loginspector -ip="192.168.1.1,10.0.0.1" access.log       # Multiple IPs
  loginspector -exclude-ip="127.0.0.1" access.log          # Exclude localhost
  loginspector -bot="Googlebot,YandexBot" -exclude-ip="127.0.0.1" -method="GET,POST" access.log
```

## Output Sections

LogInspector provides comprehensive analysis across multiple sections:

### **Top IPs** (`-ips`)
Shows IP addresses with the most requests. Automatically marks known bots.
- **Default limit:** 10 entries
- **Use case:** Identify your most active visitors and detect potential bot traffic

### **HTTP Status Codes** (`-status`)
Distribution of server response codes (200, 404, 500, etc.)
- **Default limit:** 10 codes
- **Use case:** Monitor site health and error rates

### **Browser Statistics** (`-browser`)
Breakdown of browsers used by visitors (Chrome, Firefox, Safari, Edge, etc.)
- **Shows:** Percentage and request count per browser
- **Use case:** Understand your audience's browser preferences for compatibility testing

### **Device Statistics** (`-device`)
Distribution by device type (Desktop, Mobile, Tablet)
- **Shows:** Percentage and request count per device type
- **Use case:** Optimize your site for the most common device types

### **OS Statistics** (`-os`)
Operating system distribution (Windows, macOS, Linux, Android, iOS)
- **Shows:** Percentage and request count per OS
- **Use case:** Platform-specific optimization and testing priorities

### **Paths** (`-paths`)
Most frequently requested URLs
- **Default limit:** 10 paths
- **Use case:** Identify your most popular pages and resources

### **Time Distribution** (`-time`)
Hourly breakdown of request activity (00:00-01:00, 01:00-02:00, etc.)
- **Shows:** All 24 hours
- **Use case:** Understand traffic patterns and plan maintenance windows

### **Bots** (`-bots`)
Identified bot and crawler traffic breakdown
- **Default limit:** 10 bots
- **Detects:** known bots
- **Shows:** Total count at the end
- **Use case:** Analyze search engine crawler activity and detect unwanted bots

### **Requests** (`-requests`)
Detailed view of individual log entries in table format
- **Shows:** Date/Time, Exec Time, Status, IP, Domain, Method, Path, User-Agent
- **Default limit:** 50 entries (use `-limit` to override)
- **Not shown by default** - only with `-requests` flag (use with filters for best results)
- **Use case:** Debug specific errors, investigate incidents, find request patterns
- **Works with:** All filters (time ranges, status codes)

### **Suspicious IPs** (`-suspicious`)
Identifies potentially problematic IPs with:
- High error counts
- High error rates (>20% errors with ≥5 requests)
- Many 403 Forbidden responses
- **Marks:** Known bots in output
- **Use case:** Detect potential security threats, scrapers, or misbehaving clients

**Note:** Without flags, all sections are displayed. With specific flags, only those sections are shown.

## Supported Log Formats

Currently supports custom log format. Example line:
```
[u-0][08/Dec/2025:14:23:45 +0300] 0.123 0.456 200 192.168.1.1 www.example.com GET /api/users HTTP/1.1 "Mozilla/5.0 (Windows NT 10.0; Win64; x64)..." "-" 12345 10.0.0.1 server01
```

## Performance

- Handles 10M+ lines efficiently
- Buffered I/O (1MB buffer)
- Single-pass analysis
- Low memory footprint

## Output Example

```
╔══════════════════════════════════════════════════════════════════════╗
║                      🔍  LogInspector  v0.3.1                        ║
║                 Fast Web Server Access Log Analyzer                  ║
╠══════════════════════════════════════════════════════════════════════╣
║  Total requests: 60133            Bot types: 30                      ║
║  Unique IPs: 40562                IPs with errors: 3348              ║
║  Errors (4xx/5xx): 4880           Avg response time: 0.872s          ║
╚══════════════════════════════════════════════════════════════════════╝

══════════════════════════════ Top IPs ═══════════════════════════════
66.249.69.105                            949 (bot: Googlebot)
75.97.206.53                             874
...

═════════════════════════ HTTP Status Codes ═══════════════════════════
200                                      55253
404                                      3842
301                                      890
403                                      85
500                                      63
...

═════════════════════════ Browser Statistics ═════════════════════════
Chrome                          83.02% (43449 requests)
Firefox                          9.79% (5121 requests)
Safari                           2.69% (1409 requests)
...

══════════════════════════ Device Statistics ═════════════════════════
Desktop                         92.79% (48560 requests)
Mobile                           7.17% (3753 requests)
Tablet                           0.04% (21 requests)

═══════════════════════════ OS Statistics ════════════════════════════
Windows                         45.23% (23680 requests)
Linux                           28.91% (15134 requests)
macOS                           12.45% (6514 requests)
Android                          8.12% (4251 requests)
iOS                              3.89% (2034 requests)
...

═══════════════════════════════ Paths ════════════════════════════════
/                                            12453
/api/v1/users                                 8721
/static/css/main.css                          5632
/products                                     3891
/about                                        2145
...

══════════════════════════ Time Distribution ══════════════════════════
00:00 - 01:00    ▓░░░░░░░░░  1234
01:00 - 02:00    ▓░░░░░░░░░   876
02:00 - 03:00    ▒░░░░░░░░░   542
...
14:00 - 15:00    ▓▓▓▓▓▓▓▓▓▓  4521
15:00 - 16:00    ▓▓▓▓▓▓▓▓░░  3892
...
23:00 - 00:00    ▓▓░░░░░░░░  1654

═══════════════════════════════ Bots ═════════════════════════════════
Googlebot                                2769
VKRobotRB                                995
YandexBot                                893
...
Total: 7799

═══════════════════════════ Suspicious IPs ═══════════════════════════

Top IPs by error count (4xx/5xx):
45.142.212.61           127 errors ( 87.6% error rate, 145 total)
103.251.167.20           89 errors ( 76.1% error rate, 117 total)
185.220.101.42           45 errors (100.0% error rate, 45 total) (bot: Unknown)

Top IPs by error rate (min 5 requests):
185.220.101.42         100.0% error rate (45/45) (bot: Unknown)
45.142.212.61           87.6% error rate (127/145)
103.251.167.20          76.1% error rate (89/117)
```

## Debugging with -requests

The `-requests` flag shows detailed request logs. Most useful when combined with filters:

### Common Debugging Scenarios

**Find all server errors:**
```bash
loginspector -requests -status-code="500" access.log
```

**Investigate 404s (broken links):**
```bash
loginspector -requests -status-code="404" -limit=100 access.log
```

**Debug errors during specific time:**
```bash
loginspector -requests -status-code="5xx" \
  -from="09/Dec/2025:14:00:00" \
  -to="09/Dec/2025:14:30:00" \
  access.log
```

**See all client errors:**
```bash
loginspector -requests -status-code="4xx" access.log
```

**Audit successful requests in time window:**
```bash
loginspector -requests -status-code="2xx" \
  -from="09/Dec/2025:08:00:00" \
  -to="09/Dec/2025:09:00:00" \
  access.log
```

**Show more details (increase limit):**
```bash
loginspector -requests -status-code="500" -limit=200 access.log
```

### Example Output

```bash
$ loginspector -requests -status-code="404" -limit=5 access.log
```

```
╔══════════════════════════════════════════════════════════════════════╗
║                      🔍  LogInspector  v0.3.1                        ║
║                 Fast Web Server Access Log Analyzer                  ║
╠══════════════════════════════════════════════════════════════════════╣
║  Total requests: 1323             Bot types: 7                       ║
║  Unique IPs: 556                  IPs with errors: 556               ║
║  Errors (4xx/5xx): 1323           Avg response time: 0.604s          ║
╚══════════════════════════════════════════════════════════════════════╝

════════════════════════════ Requests ════════════════════════════════
Date/Time        | Exec  | Status | IP              | Domain               | Method | Path                           | User-Agent          
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
09/Dec 00:00:47  | 0.45s | 404    | 192.168.1.100   | www.example.com      | GET    | /static/images/missing.png     | Chrome              
09/Dec 00:00:47  | 0.45s | 404    | 192.168.1.100   | www.example.com      | GET    | /assets/file-12345.js          | Chrome              
09/Dec 00:03:43  | 1.99s | 404    | 10.0.45.201     | api.example.com      | GET    | /api/v1/users/nonexistent      | Safari              
09/Dec 00:05:52  | 0.89s | 404    | 172.16.0.55     | shop.example.com     | GET    | /products/old-item-789         | Firefox             
09/Dec 00:05:53  | 0.33s | 404    | 172.16.0.55     | shop.example.com     | GET    | /static/logo-old.png           | Firefox             

Showing 5 of 1323 entries (use -limit to show more)
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## Changelog
See [CHANGELOG.md](./CHANGELOG.md) for a list of changes and version history.

## License
[MIT](LICENSE.md)