"""Generate a realistic synthetic access log with labelled attacks.

Injected behaviours (ground truth is written to a sidecar file):
  - brute_force: many POST /login attempts with 401 from one IP in a short window
  - scanner:     one IP requesting many distinct missing paths (404)
  - exfiltration: one IP downloading unusually large responses
Normal clients browse a small set of pages with realistic status codes.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np

PAGES = ['/', '/about', '/products', '/products/42', '/blog', '/blog/post-1', '/contact', '/static/app.js', '/static/style.css']
AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0',
    'Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/605.1',
]
SCAN_AGENT = 'sqlmap/1.7'


def _line(ip, t, method, path, status, size, agent):
    stamp = t.strftime('%d/%b/%Y:%H:%M:%S %z')
    return f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"'


def generate(out_log: str, out_labels: str, n_clients: int = 200, seed: int = 42,
             start: datetime | None = None, hours: int = 24) -> dict:
    rng = np.random.default_rng(seed)
    start = start or datetime(2026, 10, 1, tzinfo=timezone.utc)
    span = hours * 3600
    lines: list[tuple[datetime, str]] = []
    labels: dict[str, str] = {}

    def rand_time():
        return start + timedelta(seconds=float(rng.uniform(0, span)))

    def ip_for(i):
        return f'10.{i // 250}.{i % 250}.{rng.integers(1, 250)}'

    # Normal clients
    for i in range(n_clients):
        ip = ip_for(i)
        agent = AGENTS[rng.integers(len(AGENTS))]
        for _ in range(int(rng.integers(5, 60))):
            t = rand_time()
            page = PAGES[rng.integers(len(PAGES))]
            status = 200 if rng.random() > 0.02 else 404
            size = int(rng.integers(500, 20000))
            lines.append((t, _line(ip, t, 'GET', page, status, size, agent)))
        if rng.random() < 0.3:
            t = rand_time()
            lines.append((t, _line(ip, t, 'POST', '/login', 302, 0, agent)))

    # Brute force: 3 attackers, 150-250 failed logins each in ~10 minutes
    for k in range(3):
        ip = f'203.0.113.{10 + k}'
        labels[ip] = 'brute_force'
        base = start + timedelta(seconds=float(rng.uniform(0, span - 900)))
        for _ in range(int(rng.integers(150, 250))):
            t = base + timedelta(seconds=float(rng.uniform(0, 600)))
            lines.append((t, _line(ip, t, 'POST', '/login', 401, 180, 'python-requests/2.31')))

    # Scanner: 1 attacker probing many missing paths with a scanner UA
    ip = '198.51.100.7'
    labels[ip] = 'scanner'
    base = start + timedelta(seconds=float(rng.uniform(0, span - 1800)))
    for j in range(300):
        t = base + timedelta(seconds=float(rng.uniform(0, 1200)))
        lines.append((t, _line(ip, t, 'GET', f'/admin/backup_{j}.zip', 404, 150, SCAN_AGENT)))

    # Exfiltration: 1 client pulling very large responses repeatedly
    ip = '192.0.2.99'
    labels[ip] = 'exfiltration'
    base = start + timedelta(seconds=float(rng.uniform(0, span - 3600)))
    for _ in range(40):
        t = base + timedelta(seconds=float(rng.uniform(0, 3000)))
        lines.append((t, _line(ip, t, 'GET', '/downloads/dataset.tar.gz', 200,
                               int(rng.integers(80_000_000, 200_000_000)), AGENTS[0])))

    lines.sort(key=lambda x: x[0])
    Path(out_log).write_text('\n'.join(text for _, text in lines) + '\n')
    Path(out_labels).write_text(json.dumps(labels, indent=2))
    return {'lines': len(lines), 'malicious_ips': len(labels)}
