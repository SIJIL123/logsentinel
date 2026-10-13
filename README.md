# logsentinel

logsentinel scans web server access logs for suspicious clients. It parses Apache and nginx "combined" logs, builds a behaviour profile for each client IP, applies rules for brute force, scanning and data exfiltration, and uses an IsolationForest to flag clients that look unusual. It writes an alerts CSV and a self-contained HTML report.

## How it works

1. **Parse:** `logsentinel/parser.py` reads each line and counts lines it can't parse.
2. **Profile:** `logsentinel/detect.py` aggregates events per client IP: request count, error rate, failed logins, 404s, distinct paths, response sizes, and whether the user agent looks like a scanner.
3. **Rules:** transparent checks, with thresholds you can change in `RULE_THRESHOLDS`:
   - **brute_force:** 50 or more failed logins (401 on `POST /login`) from one IP
   - **scanner:** 100 or more 404s, or a known scanner user agent such as sqlmap, nikto, nmap, masscan, or zgrab
   - **exfiltration:** a single response of 50 MB or more
4. **Anomaly score:** an IsolationForest over the same features. Clients in the top `contamination` fraction are flagged.
5. **Output:** `alerts.csv` lists flagged clients and their evidence. `report.html` is a standalone page with a table of the same data.

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Create a synthetic log with labelled attacks (for testing)
python -m logsentinel.cli generate --out access.log --labels labels.json

# Analyse a log
python -m logsentinel.cli analyze access.log --out-dir out

# Score detections against labels
python -m logsentinel.cli evaluate access.log --labels labels.json
```

## Results on the synthetic test log

The synthetic log has 6,902 lines from 205 clients, including 5 injected attackers: 3 brute-force IPs, 1 scanner, and 1 exfiltration client.

- All 5 attackers were flagged, with no false positives.
- Precision 1.000, recall 1.000.

Read these numbers with the limitations below. The injected attacks are extreme, so the rules catch them easily. The result shows the pipeline works end to end. It does not show how well it performs on real traffic.

## Limitations

- **The test data is too easy.** The attacks are much more obvious than real attacks. Real evaluation needs real or realistic logs.
- **The IsolationForest added nothing in the test run.** Every flagged client was already caught by a rule. Its value on subtler anomalies is untested.
- **The thresholds are hand-picked** and haven't been tuned on real logs.
- **Real traffic causes false positives.** Shared corporate IPs, NAT gateways, and legitimate crawlers can all trigger these rules.
- **Only the combined log format is supported.** Other formats need a different regex in `parser.py`.
- **Single-file, batch analysis only.** There is no streaming mode, no IP allowlist, and no alert delivery.

## Tests

```bash
pytest -q
```

The 10 tests cover parsing, each rule, reproducible data generation, end-to-end detection on the synthetic log, and the CLI.

## Project layout

| Path | Purpose |
| --- | --- |
| `logsentinel/parser.py` | Log line parsing |
| `logsentinel/detect.py` | Client features, rules, and anomaly scoring |
| `logsentinel/generate.py` | Synthetic log generator with labelled attacks |
| `logsentinel/report.py` | Alerts CSV and HTML report |
| `logsentinel/cli.py` | Command-line interface |
| `tests/test_logsentinel.py` | pytest suite |

## License

MIT
