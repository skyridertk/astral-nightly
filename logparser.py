#!/usr/bin/env python3
"""
Log Parser CLI - Astral Nightly Build #2
Parses nginx/apache access logs and generates summary reports.

Usage:
    python logparser.py /var/log/nginx/access.log
    python logparser.py access.log --format apache --output report.json
    cat access.log | python logparser.py -
"""

import re
import sys
import json
import argparse
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Iterator, Dict, List, Optional


class LogEntry:
    """Represents a parsed log entry."""
    
    def __init__(self, ip: str, timestamp: str, method: str, path: str,
                 status: int, size: int, user_agent: str, referrer: str = "-"):
        self.ip = ip
        self.timestamp = timestamp
        self.method = method
        self.path = path
        self.status = status
        self.size = size
        self.user_agent = user_agent
        self.referrer = referrer
    
    @property
    def is_error(self) -> bool:
        return self.status >= 400
    
    @property
    def is_success(self) -> bool:
        return 200 <= self.status < 300


class LogParser:
    """Parser for nginx and apache access logs."""
    
    # nginx: 127.0.0.1 - - [10/Feb/2025:14:32:01 +0000] "GET /api HTTP/1.1" 200 512 "-" "Mozilla/5.0"
    # apache: 127.0.0.1 - - [10/Feb/2025:14:32:01 +0000] "GET /api HTTP/1.1" 200 512 "-" "Mozilla/5.0"
    NGINX_PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+'           # IP address
        r'\S+\s+'                     # ident
        r'\S+\s+'                     # auth user
        r'\[(?P<timestamp>[^\]]+)\]\s+'  # timestamp
        r'"(?P<method>\S+)\s+'       # method
        r'(?P<path>\S+)\s+'          # path
        r'[^"]*"\s+'                 # protocol
        r'(?P<status>\d+)\s+'        # status code
        r'(?P<size>\d+)\s+'          # response size
        r'"(?P<referrer>[^"]*)"\s+'  # referrer
        r'"(?P<user_agent>[^"]*)"'   # user agent
    )
    
    def __init__(self, format_type: str = "auto"):
        self.format_type = format_type
    
    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single log line."""
        line = line.strip()
        if not line:
            return None
        
        match = self.NGINX_PATTERN.match(line)
        if not match:
            return None
        
        data = match.groupdict()
        return LogEntry(
            ip=data['ip'],
            timestamp=data['timestamp'],
            method=data['method'],
            path=data['path'],
            status=int(data['status']),
            size=int(data['size']),
            user_agent=data['user_agent'],
            referrer=data['referrer']
        )
    
    def parse_file(self, filepath: str) -> Iterator[LogEntry]:
        """Parse a log file."""
        path = Path(filepath)
        if not path.exists():
            if filepath == '-':
                for line in sys.stdin:
                    entry = self.parse_line(line)
                    if entry:
                        yield entry
            else:
                raise FileNotFoundError(f"Log file not found: {filepath}")
        else:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    entry = self.parse_line(line)
                    if entry:
                        yield entry


class LogAnalyzer:
    """Analyzes parsed log entries and generates reports."""
    
    def __init__(self, entries: List[LogEntry]):
        self.entries = entries
    
    def analyze(self) -> Dict:
        """Generate comprehensive analysis."""
        if not self.entries:
            return {"error": "No valid log entries found"}
        
        total_requests = len(self.entries)
        total_bytes = sum(e.size for e in self.entries)
        error_count = sum(1 for e in self.entries if e.is_error)
        success_count = sum(1 for e in self.entries if e.is_success)
        
        # Status code distribution
        status_codes = Counter(e.status for e in self.entries)
        
        # HTTP methods
        methods = Counter(e.method for e in self.entries)
        
        # Top IPs
        top_ips = Counter(e.ip for e in self.entries).most_common(10)
        
        # Top paths
        top_paths = Counter(e.path for e in self.entries).most_common(10)
        
        # Top user agents
        top_agents = Counter(e.user_agent for e in self.entries).most_common(5)
        
        # Status code categories
        status_categories = defaultdict(int)
        for e in self.entries:
            category = f"{e.status // 100}xx"
            status_categories[category] += 1
        
        # Path-based analysis (find 404s, errors by path)
        error_paths = Counter(e.path for e in self.entries if e.is_error).most_common(10)
        
        return {
            "summary": {
                "total_requests": total_requests,
                "total_bytes": total_bytes,
                "total_bytes_human": self._human_readable_size(total_bytes),
                "error_rate": round(error_count / total_requests * 100, 2),
                "success_rate": round(success_count / total_requests * 100, 2),
                "avg_response_size": round(total_bytes / total_requests, 2) if total_requests else 0
            },
            "status_codes": dict(status_codes),
            "status_categories": dict(status_categories),
            "methods": dict(methods),
            "top_ips": [{"ip": ip, "count": count} for ip, count in top_ips],
            "top_paths": [{"path": path, "count": count} for path, count in top_paths],
            "top_user_agents": [{"agent": agent[:60], "count": count} for agent, count in top_agents],
            "error_paths": [{"path": path, "errors": count} for path, count in error_paths]
        }
    
    @staticmethod
    def _human_readable_size(size_bytes: int) -> str:
        """Convert bytes to human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.2f} TB"


def print_report(report: Dict, format_type: str = "text"):
    """Print report in specified format."""
    if format_type == "json":
        print(json.dumps(report, indent=2))
        return
    
    if "error" in report:
        print(f"Error: {report['error']}")
        return
    
    summary = report["summary"]
    
    print("=" * 60)
    print("📊 LOG ANALYSIS REPORT")
    print("=" * 60)
    
    print(f"\n📈 SUMMARY")
    print(f"   Total Requests:    {summary['total_requests']:,}")
    print(f"   Total Traffic:     {summary['total_bytes_human']}")
    print(f"   Avg Response:      {summary['avg_response_size']:.0f} bytes")
    print(f"   Success Rate:      {summary['success_rate']}%")
    print(f"   Error Rate:        {summary['error_rate']}%")
    
    print(f"\n📊 STATUS CODES")
    for code, count in sorted(report["status_codes"].items()):
        pct = count / summary['total_requests'] * 100
        bar = "█" * int(pct / 2)
        print(f"   {code}: {count:>6,} ({pct:>5.1f}%) {bar}")
    
    print(f"\n🌐 HTTP METHODS")
    for method, count in report["methods"].most_common() if hasattr(report["methods"], 'most_common') else sorted(report["methods"].items(), key=lambda x: -x[1]):
        print(f"   {method:>7}: {count:,}")
    
    print(f"\n🔝 TOP 10 PATHS")
    for item in report["top_paths"]:
        path = item['path'][:50] + "..." if len(item['path']) > 50 else item['path']
        print(f"   {item['count']:>6,}  {path}")
    
    print(f"\n🌍 TOP 10 IPs")
    for item in report["top_ips"]:
        print(f"   {item['count']:>6,}  {item['ip']}")
    
    if report["error_paths"]:
        print(f"\n⚠️  TOP ERROR PATHS")
        for item in report["error_paths"][:5]:
            path = item['path'][:45] + "..." if len(item['path']) > 45 else item['path']
            print(f"   {item['errors']:>6,}  {path}")
    
    print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Parse nginx/apache access logs and generate summary reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /var/log/nginx/access.log
  %(prog)s access.log --output report.json
  cat access.log | %(prog)s -
        """
    )
    parser.add_argument("logfile", help="Path to log file (use '-' for stdin)")
    parser.add_argument("--format", "-f", choices=["text", "json"], default="text",
                       help="Output format (default: text)")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    parser.add_argument("--filter-status", type=int, help="Filter by status code")
    parser.add_argument("--filter-ip", help="Filter by IP address")
    
    args = parser.parse_args()
    
    # Parse logs
    log_parser = LogParser()
    try:
        entries = list(log_parser.parse_file(args.logfile))
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    
    if not entries:
        print("No valid log entries found.", file=sys.stderr)
        sys.exit(1)
    
    # Apply filters
    if args.filter_status:
        entries = [e for e in entries if e.status == args.filter_status]
    if args.filter_ip:
        entries = [e for e in entries if e.ip == args.filter_ip]
    
    # Analyze
    analyzer = LogAnalyzer(entries)
    report = analyzer.analyze()
    
    # Output
    if args.output:
        with open(args.output, 'w') as f:
            if args.format == "json":
                json.dump(report, f, indent=2)
            else:
                # Redirect print to file
                import io
                old_stdout = sys.stdout
                sys.stdout = io.StringIO()
                print_report(report, "text")
                output = sys.stdout.getvalue()
                sys.stdout = old_stdout
                f.write(output)
        print(f"Report saved to: {args.output}")
    else:
        print_report(report, args.format)


if __name__ == "__main__":
    main()
