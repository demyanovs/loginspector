[![](https://github.com/demyanovs/loginspector/actions/workflows/go.yml/badge.svg)](https://github.com/demyanovs/loginspector/actions) [![Go Reference](https://pkg.go.dev/badge/github.com/demyanovs/loginspector.svg)](https://pkg.go.dev/github.com/demyanovs/loginspector)

# LogInspector

Fast and powerful web server access log inspector.

## Features

- Fast parsing of large log files (buffered I/O)
- Comprehensive statistics (IPs, browsers, devices, OS, bots)
- Flexible filtering (time ranges, status codes)
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

Flags:
  -ips            Top IPs with most requests
  -status         HTTP status code distribution
  -browser        Browser usage statistics
  -device         Device type distribution
  -os             Operating system distribution
  -paths          Most requested URLs
  -time           Hourly request distribution
  -bots           Bot/crawler statistics
  -from           Filter logs from this time (format: 08/Dec/2025:08:30:00)
  -to             Filter logs until this time (format: 08/Dec/2025:18:30:00)
  -status-code    Include only these status codes (comma-separated, ranges: 2xx,3xx,4xx,5xx)
  -exclude-status Exclude these status codes (comma-separated, ranges: 2xx,3xx,4xx,5xx)
  -limit int      Max items per section (default: varies by section)

Examples:
  loginspector access.log                       # All sections
  loginspector -bots access.log                 # Only bots
  loginspector -bots -ips -limit=20 access.log  # Top 20 bots and IPs
  loginspector -from="08/Dec/2025:08:00:00" -to="08/Dec/2025:18:00:00" access.log  # Time range
  loginspector -from="07/Dec/2025:12:00:00" access.log  # From specific time onwards
  loginspector -status-code="200" access.log    # Only 200 OK
  loginspector -status-code="4xx,5xx" access.log  # Only errors
  loginspector -exclude-status="2xx" access.log  # All except success
  loginspector -from="..." -status-code="5xx" access.log  # Combine filters
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

### **Suspicious IPs** (shown by default)
Automatically shown when errors exist. Identifies IPs with:
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
=========================================
        LogInspector (v0.1.0)
=========================================
Total requests: 60,133
Unique IPs: 40,562
Errors (4xx/5xx): 4,880
Avg response time: 0.872 s
Bot types: 30
IPs with errors: 3,348
=========================================

========== Top IPs ==========
66.249.69.105                            949 (bot: Googlebot)
75.97.206.53                             874
...

========== Browser Statistics ==========
Chrome                          83.02% (43449 requests)
Firefox                          9.79% (5121 requests)
Safari                           2.69% (1409 requests)
...

========== Device Statistics ==========
Desktop                         92.79% (48560 requests)
Mobile                           7.17% (3753 requests)
Tablet                           0.04% (21 requests)

========== Bots ==========
Googlebot                                2769
VKRobotRB                                995
YandexBot                                893
...
Total: 7799
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](LICENSE.md)