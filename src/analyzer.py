"""
Log Analyzer & Threat Detector
Author: Nuzhat Atiqua Nafis
Run with no arguments  -> interactive prompts
Run with flags         -> classic command-line mode
"""

import argparse
import os
import re
import sys
from collections import defaultdict
from datetime import datetime

from patterns import THREAT_PATTERNS, LOG_PATTERN
from pdf_report import generate_pdf_report
import prompts


def analyze_log_file(filepath, log_type="apache"):
    findings, total_lines, parsed_lines = [], 0, 0
    ip_counts, ip_errors, auth_hits = defaultdict(int), defaultdict(int), defaultdict(int)

    with open(filepath, "r", errors="ignore") as f:
        for line_num, line in enumerate(f, 1):
            total_lines += 1
            line = line.strip()
            if not line:
                continue

            if log_type == "apache":
                m = LOG_PATTERN.match(line)
                if not m:
                    continue
                parsed_lines += 1
                p = m.groupdict()
                ip = p["ip"]
                ip_counts[ip] += 1
                if p["status"].startswith("4"):
                    ip_errors[ip] += 1
                for name, info in THREAT_PATTERNS.items():
                    if info["pattern"].search(line):
                        findings.append({"line": line_num, "type": name,
                                         "severity": info["severity"], "source_ip": ip,
                                         "detail": line[:200], "timestamp": p["time"]})
            else:  # auth log
                parsed_lines += 1
                for name, info in THREAT_PATTERNS.items():
                    if info["pattern"].search(line):
                        ipm = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
                        ip = ipm.group() if ipm else "unknown"
                        auth_hits[ip] += 1
                        findings.append({"line": line_num, "type": name,
                                         "severity": info["severity"], "source_ip": ip,
                                         "detail": line[:200], "timestamp": "N/A"})

    for ip, n in auth_hits.items():
        if n > 20:
            findings.append({"line": "N/A", "type": "Brute Force Attack",
                             "severity": "Critical", "source_ip": ip,
                             "detail": f"{n} suspicious auth events", "timestamp": "Multiple"})
    for ip, n in ip_counts.items():
        if n > 200:
            findings.append({"line": "N/A", "type": "Potential Port/Web Scan",
                             "severity": "Medium", "source_ip": ip,
                             "detail": f"{n} total requests", "timestamp": "Multiple"})
        if ip_errors.get(ip, 0) > 50:
            findings.append({"line": "N/A", "type": "Potential Directory Bruteforce",
                             "severity": "High", "source_ip": ip,
                             "detail": f"{ip_errors[ip]} 4xx errors", "timestamp": "Multiple"})

    return {"file": filepath, "total_lines": total_lines, "parsed_lines": parsed_lines,
            "findings": findings,
            "top_ips": sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]}


def print_results(results):
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    print(f"\n  {'='*58}")
    print(f"  Total lines  : {results['total_lines']}")
    print(f"  Parsed lines : {results['parsed_lines']}")
    print(f"  Findings     : {len(results['findings'])}")
    print(f"  {'='*58}\n")
    for f in sorted(results["findings"], key=lambda x: order.get(x["severity"], 4)):
        print(f"  [{f['severity']:8s}] Line {str(f['line']):5s} | {f['type']}")
        print(f"             IP: {f['source_ip']:15s} | {f['detail'][:60]}\n")
    if not results["findings"]:
        print("  No threats detected.")
    print("  TOP 5 SOURCE IPs:")
    for ip, n in results["top_ips"][:5]:
        print(f"    {ip:20s} -> {n} requests")


def validate_log_file(path):
    path = os.path.expanduser(path)
    if not os.path.isfile(path):
        return f"File not found: {path}"
    return None


def save_pdf(results, log_type, save_path):
    generate_pdf_report({
        "tool_name": "Log Threat Analyzer",
        "target": results["file"],
        "scan_date": datetime.now().isoformat(),
        "extra_meta": [("Log Type:", log_type),
                       ("Lines Parsed:", f"{results['parsed_lines']} / {results['total_lines']}")],
        "findings": results["findings"],
    }, save_path, "Log Threat Analysis Report")
    print(f"\n  PDF saved to: {os.path.abspath(save_path)}\n")


# -------------------------- INTERACTIVE MODE --------------------------
def interactive_mode():
    prompts.banner("Log Threat Analyzer  (interactive mode)")
    path = os.path.expanduser(prompts.ask_text("Path to log file", validator=validate_log_file))
    log_type = prompts.ask_choice("Log type", ["apache", "auth"], "apache")

    results = analyze_log_file(path, log_type)
    print_results(results)

    if prompts.ask_yes_no("Save a PDF report?", default=True):
        name = f"log_analysis_{datetime.now():%Y%m%d_%H%M%S}.pdf"
        save_pdf(results, log_type, prompts.ask_save_path(name))


# --------------------------- COMMAND-LINE MODE ------------------------
def cli_mode(argv):
    ap = argparse.ArgumentParser(description="Log Analyzer & Threat Detector")
    ap.add_argument("-f", "--file", required=True)
    ap.add_argument("-t", "--type", default="apache", choices=["apache", "auth"])
    ap.add_argument("--pdf", metavar="PATH", help="Write PDF report to PATH")
    args = ap.parse_args(argv)

    err = validate_log_file(args.file)
    if err:
        ap.error(err)
    results = analyze_log_file(os.path.expanduser(args.file), args.type)
    print_results(results)
    if args.pdf:
        save_pdf(results, args.type, args.pdf)


def main():
    if len(sys.argv) == 1:
        interactive_mode()
    else:
        cli_mode(sys.argv[1:])


if __name__ == "__main__":
    main()
