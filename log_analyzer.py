#!/usr/bin/env python3
"""
Log analyzer: flags IP addresses with repeated failed SSH logins.

Usage:
    python log_analyzer.py sample_auth.log
    python log_analyzer.py sample_auth.log --threshold 3
"""
import argparse
import re
from collections import Counter

FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def analyze(path: str, threshold: int):
    by_ip = Counter()
    users_by_ip = {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = FAILED_RE.search(line)
            if m:
                ip, user = m.group("ip"), m.group("user")
                by_ip[ip] += 1
                users_by_ip.setdefault(ip, set()).add(user)

    total = sum(by_ip.values())
    print(f"Total failed logins found: {total}")
    print(f"Unique source IPs: {len(by_ip)}\n")

    flagged = [(ip, n) for ip, n in by_ip.most_common() if n >= threshold]
    if not flagged:
        print(f"No IPs reached the threshold of {threshold} failed attempts.")
        return
    print(f"SUSPICIOUS (>= {threshold} failed attempts)")
    for ip, n in flagged:
        users = ", ".join(sorted(users_by_ip[ip]))
        print(f"  {ip:<16} {n:>3} attempts   users tried: {users}")


def main():
    parser = argparse.ArgumentParser(description="Flag repeated failed logins")
    parser.add_argument("logfile")
    parser.add_argument("--threshold", type=int, default=5)
    args = parser.parse_args()
    analyze(args.logfile, args.threshold)


if __name__ == "__main__":
    main()
