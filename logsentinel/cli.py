"""Command-line interface: generate sample logs, analyse a log file, or evaluate detection."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from logsentinel.detect import detect
from logsentinel.generate import generate
from logsentinel.parser import parse_file
from logsentinel.report import write_alerts, write_html


def cmd_generate(args) -> int:
    info = generate(args.out, args.labels, seed=args.seed)
    print(f"wrote {info['lines']:,} lines to {args.out}; labels to {args.labels}")
    return 0


def cmd_analyze(args) -> int:
    events, bad = parse_file(args.log)
    if events.empty:
        print('error: no parseable log lines', file=sys.stderr)
        return 1
    result = detect(events, contamination=args.contamination, seed=args.seed)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    n_alerts = write_alerts(result, out / 'alerts.csv')
    summary = {'lines': len(events), 'clients': len(result), 'bad_lines': bad,
               'flagged': n_alerts}
    write_html(result, summary, out / 'report.html')
    print(f"parsed {len(events):,} lines ({bad:,} unparsed); {len(result):,} clients; {n_alerts} flagged")
    print(f"alerts -> {out / 'alerts.csv'}")
    print(f"report -> {out / 'report.html'}")
    return 0


def cmd_evaluate(args) -> int:
    events, _ = parse_file(args.log)
    result = detect(events, contamination=args.contamination, seed=args.seed)
    truth = json.loads(Path(args.labels).read_text())
    flagged = set(result.index[result['flagged']])
    actual = set(truth)
    tp = len(flagged & actual)
    precision = tp / len(flagged) if flagged else 0.0
    recall = tp / len(actual) if actual else 0.0
    print(f'malicious clients: {len(actual)}  flagged: {len(flagged)}  true positives: {tp}')
    print(f'precision: {precision:.3f}  recall: {recall:.3f}')
    missed = sorted(actual - flagged)
    if missed:
        print('missed:', ', '.join(f'{ip} ({truth[ip]})' for ip in missed))
    false_pos = sorted(flagged - actual)
    if false_pos:
        print('false positives:', ', '.join(false_pos[:10]) + (' ...' if len(false_pos) > 10 else ''))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='logsentinel', description='Detect suspicious web traffic.')
    sub = p.add_subparsers(dest='command', required=True)

    g = sub.add_parser('generate', help='write a synthetic log with labelled attacks')
    g.add_argument('--out', default='access.log')
    g.add_argument('--labels', default='labels.json')
    g.add_argument('--seed', type=int, default=42)
    g.set_defaults(func=cmd_generate)

    a = sub.add_parser('analyze', help='analyse a log and write alerts and an HTML report')
    a.add_argument('log')
    a.add_argument('--out-dir', default='out')
    a.add_argument('--contamination', type=float, default=0.02)
    a.add_argument('--seed', type=int, default=42)
    a.set_defaults(func=cmd_analyze)

    e = sub.add_parser('evaluate', help='score detections against labelled ground truth')
    e.add_argument('log')
    e.add_argument('--labels', default='labels.json')
    e.add_argument('--contamination', type=float, default=0.02)
    e.add_argument('--seed', type=int, default=42)
    e.set_defaults(func=cmd_evaluate)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
