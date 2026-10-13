"""Write alerts CSV and a self-contained HTML report."""

from __future__ import annotations

import html
from pathlib import Path

import pandas as pd


def write_alerts(result: pd.DataFrame, path: str | Path) -> int:
    alerts = result[result['flagged']].reset_index().rename(columns={'index': 'ip'})
    alerts.to_csv(path, index=False)
    return len(alerts)


def write_html(result: pd.DataFrame, summary: dict, path: str | Path) -> None:
    flagged = result[result['flagged']]
    rows = []
    for ip, r in flagged.iterrows():
        rows.append(
            '<tr>'
            f'<td>{html.escape(str(ip))}</td>'
            f'<td>{html.escape(r["rules"] or "anomaly only")}</td>'
            f'<td>{r["anomaly_score"]:.3f}</td>'
            f'<td>{int(r["requests"])}</td>'
            f'<td>{int(r["login_failures"])}</td>'
            f'<td>{int(r["not_found"])}</td>'
            f'<td>{int(r["max_bytes"]):,}</td>'
            '</tr>'
        )
    body = '\n'.join(rows) or '<tr><td colspan="7">No suspicious clients found.</td></tr>'
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>logsentinel report</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;color:#1a1a1a}}
table{{border-collapse:collapse;width:100%}}
th,td{{border-bottom:1px solid #ddd;padding:.45rem .6rem;text-align:left;font-size:.92rem}}
th{{background:#f4f4f4}}
.kpi{{display:inline-block;margin-right:2rem}}
.kpi b{{font-size:1.4rem;display:block}}
</style></head><body>
<h1>logsentinel report</h1>
<p><span class="kpi"><b>{summary['lines']:,}</b>log lines</span>
<span class="kpi"><b>{summary['clients']:,}</b>clients</span>
<span class="kpi"><b>{len(flagged):,}</b>flagged</span>
<span class="kpi"><b>{summary['bad_lines']:,}</b>unparsed lines</span></p>
<table><thead><tr><th>Client IP</th><th>Rules triggered</th><th>Anomaly score</th>
<th>Requests</th><th>Failed logins</th><th>404s</th><th>Largest response (bytes)</th></tr></thead>
<tbody>
{body}
</tbody></table>
</body></html>"""
    Path(path).write_text(doc, encoding='utf-8')
