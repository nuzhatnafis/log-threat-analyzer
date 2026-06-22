"""
Log Analyzer & Threat Detector
Author: Nuzhat Atiqua Nafis
"""

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime
from patterns import THREAT_PATTERNS, LOG_PATTERN, AUTH_LOG_PATTERN
from pdf_report import generate_pdf_report

def parse_apache_log(line):
    """Parse Apache/Nginx combined log format."""
    match = LOG_PATTERN.match(line)
    if match:
        return match.groupdict()
    return None

def analyze_log_file(filepath, log_type="apache"):
    """Analyze a log file for threats."""
    findings = []
    ip_counts = defaultdict(int)
    ip_errors = defaultdict(int)
    brute_force_candidates = defaultdict(int)
    total_lines = 0
    parsed_lines = 0

    print(f"\n  Analyzing: {filepath}")
    print(f"  Log type : {log_type}\n")

    try:
        with open(filepath, "r", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                total_lines += 1
                line = line.strip()
                if not line:
                    continue

                # Parse the line based on type
                parsed = None
                if log_type == "apache":
                    parsed = parse_apache_log(line)
                    if parsed:
                        parsed_lines += 1
                        ip = parsed.get("ip", "unknown")
                        status = parsed.get("status", "")
                        path = parsed.get("path", "")

                        ip_counts[ip] += 1

                        # Count 4xx errors per IP (recon indicator)
                        if status.startswith("4"):
                            ip_errors[ip] += 1

                        # Full line search for patterns
                        search_text = line
                        for threat_name, threat_info in THREAT_PATTERNS.items():
                            if threat_info["pattern"].search(search_text):
                                findings.append({
                                    "line": line_num,
                                    "type": threat_name,
                                    "severity": threat_info["severity"],
                                    "source_ip": ip,
                                    "detail": line[:200],
                                    "timestamp": parsed.get("time", "N/A")
                                })

                elif log_type == "auth":
                    # Search auth logs
                    for threat_name, threat_info in THREAT_PATTERNS.items():
                        if threat_info["pattern"].search(line):
                            # Extract IP from auth log if present
                            ip_match = re.search(
                                r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line
                            )
                            ip = ip_match.group() if ip_match else "unknown"
                            brute_force_candidates[ip] += 1

                            findings.append({
                                "line": line_num,
                                "type": threat_name,
                                "severity": threat_info["severity"],
                                "source_ip": ip,
                                "detail": line[:200],
                                "timestamp": "N/A"
                            })
                    parsed_lines += 1

    except FileNotFoundError:
        print(f"  ERROR: File not found: {filepath}")
        return None

    # Detect potential brute force (>20 failed attempts from one IP)
    for ip, count in brute_force_candidates.items():
        if count > 20:
            findings.append({
                "line": "N/A",
                "type": "Brute Force Attack",
                "severity": "Critical",
                "source_ip": ip,
                "detail": f"{count} failed authentication attempts",
                "timestamp": "Multiple"
            })

    # Detect scanning (>200 requests OR >50 errors from single IP)
    for ip, count in ip_counts.items():
        if count > 200:
            findings.append({
                "line": "N/A",
                "type": "Potential Port/Web Scan",
                "severity": "Medium",
                "source_ip": ip,
                "detail": f"{count} total requests from this IP",
                "timestamp": "Multiple"
            })
        if ip_errors.get(ip, 0) > 50:
            findings.append({
                "line": "N/A",
                "type": "Potential Directory Bruteforce",
                "severity": "High",
                "source_ip": ip,
                "detail": f"{ip_errors[ip]} 4xx errors — possible dir brute force",
                "timestamp": "Multiple"
            })

    return {
        "file": filepath,
        "total_lines": total_lines,
        "parsed_lines": parsed_lines,
        "findings": findings,
        "top_ips": sorted(
            ip_counts.items(), key=lambda x: x[1], reverse=True
        )[:10]
    }

def print_results(results):
    """Print analysis results to console."""
    if not results:
        return

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    sorted_findings = sorted(
        results["findings"],
        key=lambda x: severity_order.get(x["severity"], 4)
    )

    print(f"  {'='*58}")
    print(f"  Total lines  : {results['total_lines']}")
    print(f"  Parsed lines : {results['parsed_lines']}")
    print(f"  Findings     : {len(results['findings'])}")
    print(f"  {'='*58}\n")

    if sorted_findings:
        print("  THREAT FINDINGS:")
        print(f"  {'-'*58}")
        for f in sorted_findings:
            sev = f['severity']
            marker = {"Critical": "!!!", "High": "!! ", "Medium": "!  ", "Low": "   "}.get(sev, "   ")
            print(f"  [{marker}] [{sev:8s}] Line {str(f['line']):6s} | "
                  f"{f['type']}")
            print(f"           IP: {f['source_ip']:15s} | {f['detail'][:60]}")
            print()
    else:
        print("  No threats detected.")

    print(f"\n  TOP 5 SOURCE IPs:")
    for ip, count in results["top_ips"][:5]:
        print(f"    {ip:20s} → {count} requests")

def main():
    parser = argparse.ArgumentParser(
        description="Log Analyzer & Threat Detector"
    )
    parser.add_argument("-f", "--file", required=True,
                        help="Path to log file")
    parser.add_argument("-t", "--type", default="apache",
                        choices=["apache", "auth"],
                        help="Log type (default: apache)")
    parser.add_argument("--save", action="store_true",
                        help="Save JSON report")
    args = parser.parse_args()

    print(f"\n{'='*60}")
    print(f"  Log Analyzer & Threat Detector")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    results = analyze_log_file(args.file, args.type)
    if results:
        print_results(results)

        if args.save:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    report_for_pdf = {
        "tool_name": "Log Threat Analyzer",
        "target": args.file,
        "scan_date": datetime.now().isoformat(),
        "extra_meta": [
            ("Log Type:", args.type),
            ("Lines Parsed:", f"{results['parsed_lines']} / {results['total_lines']}"),
        ],
        "findings": results["findings"],
    }

    if args.save in ("json", "both"):
        json_out = f"reports/analysis_{ts}.json"
        with open(json_out, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n  JSON report saved to: {json_out}")

    if args.save in ("pdf", "both"):
        pdf_out = f"reports/analysis_{ts}.pdf"
        generate_pdf_report(report_for_pdf, pdf_out, "Log Threat Analysis Report")
        print(f"  PDF report saved to : {pdf_out}")

if __name__ == "__main__":
    main()