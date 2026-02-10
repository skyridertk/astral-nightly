# Log Parser CLI

A fast, minimal log analyzer for nginx and apache access logs. Built for DevOps engineers who need quick insights without heavy tooling.

## Features

- 📊 **Summary stats**: requests, bandwidth, error rates
- 🔝 **Top lists**: IPs, paths, user agents, status codes
- 🎯 **Smart filtering**: by status code or IP
- 📁 **Multiple outputs**: human-readable text or JSON
- 🚀 **Pipe-friendly**: works with stdin for quick one-liners

## Install

```bash
# Clone and use directly
git clone https://github.com/skyridertk/astral-nightly.git
cd astral-nightly
python logparser.py /var/log/nginx/access.log
```

No dependencies beyond Python 3.7+.

## Usage

```bash
# Basic analysis
python logparser.py /var/log/nginx/access.log

# JSON output for piping to other tools
python logparser.py access.log --format json --output report.json

# Pipe from another command
cat access.log | python logparser.py -
grep "2025-02-10" access.log | python logparser.py -

# Filter by status code
python logparser.py access.log --filter-status 404

# Filter by IP
python logparser.py access.log --filter-ip 192.168.1.100
```

## Sample Output

```
============================================================
📊 LOG ANALYSIS REPORT
============================================================

📈 SUMMARY
   Total Requests:    15,432
   Total Traffic:     245.67 MB
   Avg Response:      16649 bytes
   Success Rate:      94.23%
   Error Rate:        5.77%

📊 STATUS CODES
   200: 14,543 ( 94.2%) █████████████████████████████████████████
   404:    512 (  3.3%) █
   500:    234 (  1.5%) █
   301:    143 (  0.9%) 

🌐 HTTP METHODS
      GET: 14,232
     POST: 1,100
    HEAD:    100

🔝 TOP 10 PATHS
      3,421  /api/v1/users
      2,100  /api/v1/products
      1,543  /static/main.css

🌍 TOP 10 IPs
      2,341  203.0.113.45
      1,890  198.51.100.22
      1,234  192.168.1.100

⚠️  TOP ERROR PATHS
        89  /api/v1/legacy-endpoint
        45  /wp-admin/admin-ajax.php

============================================================
```

## Log Format Support

Works with standard nginx and apache combined log format:

```
127.0.0.1 - - [10/Feb/2025:14:32:01 +0000] "GET /api HTTP/1.1" 200 512 "-" "Mozilla/5.0"
```

## Integration Ideas

- **Daily cron**: Run nightly and email summary
- **CI/CD**: Check error rates after deployments
- **Monitoring**: Alert if error rate spikes
- **Analytics**: JSON output to ELK/Loki

```bash
# Example: daily report via cron
0 9 * * * /usr/bin/python3 /opt/logparser.py /var/log/nginx/access.log --format json | jq '.summary.error_rate' | awk '{if($1>5) print "High error rate: " $1}' | mail -s "Daily Log Report" ops@example.com
```

## Built By

Astral Nightly Build — minimal tools for DevOps engineers.

⚡ Built with coffee at 2 AM.
