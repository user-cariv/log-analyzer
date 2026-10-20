# Log Analyzer

A Python script that reads an SSH authentication log and flags IP addresses with repeated failed logins — the kind of pattern a SOC analyst looks for when spotting brute-force attempts.

## Features
- Parses `Failed password` lines with a regular expression
- Counts failed attempts per source IP
- Lists which usernames each IP tried
- Configurable threshold for "suspicious"

## Usage
```bash
python log_analyzer.py sample_auth.log
python log_analyzer.py sample_auth.log --threshold 3
```

`sample_auth.log` contains made-up log lines using documentation IP ranges, so no real data is involved.

## Example output
```
Total failed logins found: 14
Unique source IPs: 3

SUSPICIOUS (>= 5 failed attempts)
  198.51.100.77      7 attempts   users tried: admin, pi, root, ubuntu
  203.0.113.45       6 attempts   users tried: admin, oracle, root, test
```
*(Add a screenshot of your own run here.)*

## What I learned
- Reading and parsing log files in Python
- Using regular expressions and `collections.Counter`
- How brute-force login attempts look in logs

## Ideas to extend
- Add timestamps and detect bursts within a time window
- Export a CSV report
- Support other log formats (web server logs)
