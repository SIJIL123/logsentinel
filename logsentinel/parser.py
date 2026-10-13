"""Parse Apache/nginx 'combined' format access logs into a DataFrame."""

from __future__ import annotations

import re
from datetime import datetime

import pandas as pd

LINE_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\S+)'
    r'(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?'
)
TIME_FMT = '%d/%b/%Y:%H:%M:%S %z'


def parse_line(line: str) -> dict | None:
    """Return a dict for one log line, or None if it does not match."""
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    raw_bytes = m.group('bytes')
    return {
        'ip': m.group('ip'),
        'time': datetime.strptime(m.group('time'), TIME_FMT),
        'method': m.group('method'),
        'path': m.group('path'),
        'status': int(m.group('status')),
        'bytes': 0 if raw_bytes == '-' else int(raw_bytes),
        'agent': m.group('agent') or '',
    }


def parse_file(path: str) -> tuple[pd.DataFrame, int]:
    """Parse a log file. Returns (events, number_of_unparseable_lines)."""
    rows, bad = [], 0
    with open(path, encoding='utf-8', errors='replace') as fh:
        for line in fh:
            if not line.strip():
                continue
            rec = parse_line(line)
            if rec is None:
                bad += 1
            else:
                rows.append(rec)
    df = pd.DataFrame(rows, columns=['ip', 'time', 'method', 'path', 'status', 'bytes', 'agent'])
    return df, bad
