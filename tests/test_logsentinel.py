import json

import pandas as pd

from logsentinel.cli import main
from logsentinel.detect import client_features, detect, rule_hits
from logsentinel.generate import generate
from logsentinel.parser import parse_file, parse_line

SAMPLE = '203.0.113.5 - - [01/Oct/2026:10:00:00 +0000] "POST /login HTTP/1.1" 401 180 "-" "curl/8"'


def test_parse_line_extracts_fields():
    rec = parse_line(SAMPLE)
    assert rec['ip'] == '203.0.113.5'
    assert rec['method'] == 'POST'
    assert rec['path'] == '/login'
    assert rec['status'] == 401
    assert rec['bytes'] == 180
    assert rec['time'].year == 2026


def test_parse_line_handles_dash_bytes_and_bad_lines():
    assert parse_line(SAMPLE.replace(' 180 ', ' - '))['bytes'] == 0
    assert parse_line('not a log line') is None


def test_parse_file_counts_bad_lines(tmp_path):
    f = tmp_path / 'a.log'
    f.write_text(SAMPLE + '\n' + 'garbage\n\n')
    df, bad = parse_file(str(f))
    assert len(df) == 1
    assert bad == 1


def _events(rows):
    return pd.DataFrame(rows, columns=['ip', 'time', 'method', 'path', 'status', 'bytes', 'agent'])


def test_login_failure_rate_and_rule_fire():
    rows = [('1.1.1.1', None, 'POST', '/login', 401, 100, 'x')] * 60
    feats = client_features(_events(rows))
    assert feats.loc['1.1.1.1', 'login_failures'] == 60
    assert feats.loc['1.1.1.1', 'login_fail_rate'] == 1.0
    assert rule_hits(feats).loc['1.1.1.1', 'brute_force']


def test_scanner_agent_triggers_rule():
    rows = [('2.2.2.2', None, 'GET', '/x', 404, 0, 'sqlmap/1.7')]
    hits = rule_hits(client_features(_events(rows)))
    assert hits.loc['2.2.2.2', 'scanner']


def test_exfiltration_rule_on_large_response():
    rows = [('3.3.3.3', None, 'GET', '/big', 200, 100_000_000, 'x')]
    assert rule_hits(client_features(_events(rows))).loc['3.3.3.3', 'exfiltration']


def test_detect_returns_empty_for_no_events():
    assert detect(_events([])).empty


def test_generate_is_reproducible_and_labels_three_kinds(tmp_path):
    a, la = tmp_path / 'a.log', tmp_path / 'a.json'
    b, lb = tmp_path / 'b.log', tmp_path / 'b.json'
    generate(str(a), str(la), n_clients=20, seed=5)
    generate(str(b), str(lb), n_clients=20, seed=5)
    assert a.read_text() == b.read_text()
    labels = json.loads(la.read_text())
    assert set(labels.values()) == {'brute_force', 'scanner', 'exfiltration'}


def test_end_to_end_detects_injected_attackers(tmp_path):
    log, labels = tmp_path / 'access.log', tmp_path / 'labels.json'
    generate(str(log), str(labels), n_clients=200, seed=42)
    events, bad = parse_file(str(log))
    assert bad == 0
    result = detect(events, seed=42)
    truth = json.loads(labels.read_text())
    caught = set(result.index[result['flagged']]) & set(truth)
    assert caught == set(truth), f'missed {set(truth) - caught}'


def test_cli_full_flow(tmp_path, capsys):
    log, labels, out = tmp_path / 'access.log', tmp_path / 'labels.json', tmp_path / 'out'
    assert main(['generate', '--out', str(log), '--labels', str(labels)]) == 0
    assert main(['analyze', str(log), '--out-dir', str(out)]) == 0
    assert (out / 'alerts.csv').exists()
    html = (out / 'report.html').read_text()
    assert '<h1>logsentinel report</h1>' in html
    assert main(['evaluate', str(log), '--labels', str(labels)]) == 0
    assert 'recall: 1.000' in capsys.readouterr().out
