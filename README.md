# logsentinel

logsentinel looks through web server access logs for clients that behave suspiciously. It reads Apache and nginx logs in the combined format, builds a profile for each client IP, and checks for three things with simple rules: repeated failed logins, scanning for missing pages, and very large downloads. An IsolationForest also scores every client, so it can flag unusual behaviour the rules miss.

The output is an alerts CSV and an HTML report you can open in a browser.

## How it works

1. **Parse:** `logsentinel/parser.py` reads each line and counts the ones it can't parse.
2. **Profile:** `logsentinel/detect.py` summarises each IP: number of requests, error rate, failed logins, 404s, distinct paths, response sizes, and whether the user agent looks like a scanner.
3. **Rules:** these are plain checks, and the thresholds are in `RULE_THRESHOLDS` so you can change them.
   - **brute_force:** 50 or more failed logins (401 on `POST /login`) from one IP
   - **scanner:** 100 or more 404s, or a user agent like sqlmap, nikto, nmap, masscan or zgrab
   - **exfiltration:** a single response of 50 MB or more
4. **Anomaly score:** an IsolationForest is fitted on the same features. The top `contamination` fraction of clients gets flagged.
5. **Output:** `alerts.csv` lists the flagged clients with the evidence, and `report.html` shows the same data as a table.

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Make a test log with known attackers in it
python -m logsentinel.cli generate --out access.log --labels labels.json

# Analyse a log
python -m logsentinel.cli analyze access.log --out-dir out

# Compare detections with the known attackers
python -m logsentinel.cli evaluate access.log --labels labels.json
```

## Results on the test log

The test log has 6,902 lines from 205 clients, including 5 attackers I planted: 3 brute-force IPs, 1 scanner and 1 exfiltration client. All 5 were flagged, with no false positives.

The attacks are very obvious, so the rules catch them easily. This shows the pipeline runs end to end. It doesn't show how well it works on real traffic.

## Limitations

- **The test log is too easy.** Real attacks are much quieter, so I haven't tested it on realistic traffic yet.
- **The IsolationForest added nothing in this test.** Every flagged client was already caught by a rule, so I can't yet say what it adds.
- **The thresholds are guesses.** I haven't tuned them on real logs.
- **Real traffic will cause false positives.** Shared corporate IPs, NAT gateways and legitimate crawlers can all trip these rules.
- **Only the combined log format is supported.** Other formats need a different regex in `parser.py`.
- **Batch only.** There's no live streaming, IP allowlist or alert delivery yet.

## Tests

```bash
pytest -q
```

There are 10 tests covering parsing, each rule, reproducible data generation, end-to-end detection on the test log, and the CLI.

## Layout

| Path | What it does |
| --- | --- |
| `logsentinel/parser.py` | Log line parsing |
| `logsentinel/detect.py` | Client features, rules and anomaly scoring |
| `logsentinel/generate.py` | Test log generator with planted attackers |
| `logsentinel/report.py` | Alerts CSV and HTML report |
| `logsentinel/cli.py` | Command-line interface |
| `tests/test_logsentinel.py` | Tests |

## License

MIT
