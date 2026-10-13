"""Detection: transparent rules plus IsolationForest over per-client features."""

from __future__ import annotations

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURES = ['requests', 'error_rate', 'login_posts', 'login_fail_rate',
            'distinct_paths', 'not_found', 'mean_bytes', 'max_bytes', 'scanner_agent']

RULE_THRESHOLDS = {
    'login_failures': 50,        # failed logins from one client
    'not_found': 100,            # 404s from one client
    'max_bytes': 50_000_000,     # single response larger than 50 MB
}


def client_features(events: pd.DataFrame) -> pd.DataFrame:
    """Aggregate events into one row of behaviour features per client IP."""
    if events.empty:
        return pd.DataFrame(columns=FEATURES)
    e = events.copy()
    e['is_error'] = e['status'] >= 400
    e['is_login'] = (e['path'] == '/login') & (e['method'] == 'POST')
    e['is_login_fail'] = e['is_login'] & (e['status'] == 401)
    e['is_404'] = e['status'] == 404
    e['scanner_agent'] = e['agent'].str.contains('sqlmap|nikto|nmap|masscan|zgrab', case=False, regex=True)

    g = e.groupby('ip')
    feats = pd.DataFrame({
        'requests': g.size(),
        'error_rate': g['is_error'].mean(),
        'login_posts': g['is_login'].sum(),
        'login_failures': g['is_login_fail'].sum(),
        'distinct_paths': g['path'].nunique(),
        'not_found': g['is_404'].sum(),
        'mean_bytes': g['bytes'].mean(),
        'max_bytes': g['bytes'].max(),
        'scanner_agent': g['scanner_agent'].any().astype(int),
    })
    feats['login_fail_rate'] = (feats['login_failures'] / feats['login_posts'].replace(0, pd.NA)).fillna(0.0)
    return feats


def rule_hits(feats: pd.DataFrame) -> pd.DataFrame:
    """Return a column per rule: True where the client breaks that rule."""
    hits = pd.DataFrame(index=feats.index)
    hits['brute_force'] = feats['login_failures'] >= RULE_THRESHOLDS['login_failures']
    hits['scanner'] = (feats['not_found'] >= RULE_THRESHOLDS['not_found']) | (feats['scanner_agent'] == 1)
    hits['exfiltration'] = feats['max_bytes'] >= RULE_THRESHOLDS['max_bytes']
    return hits


def score(feats: pd.DataFrame, contamination: float = 0.02, seed: int = 42) -> pd.Series:
    """Anomaly score per client (higher = more anomalous) from IsolationForest."""
    if len(feats) < 10:
        return pd.Series(0.0, index=feats.index)
    X = StandardScaler().fit_transform(feats[FEATURES].astype(float))
    model = IsolationForest(contamination=contamination, random_state=seed, n_estimators=200)
    model.fit(X)
    return pd.Series(-model.score_samples(X), index=feats.index)


def detect(events: pd.DataFrame, contamination: float = 0.02, seed: int = 42) -> pd.DataFrame:
    """Return one row per client with features, rule hits, anomaly score and a verdict."""
    feats = client_features(events)
    if feats.empty:
        return feats
    hits = rule_hits(feats)
    result = feats.copy()
    result['anomaly_score'] = score(feats, contamination, seed).round(4)
    result['rules'] = hits.apply(lambda r: ','.join(c for c, v in r.items() if v), axis=1)
    top_k = max(1, int(round(contamination * len(result))))
    result['flagged'] = (result['rules'] != '') | (result['anomaly_score'].rank(ascending=False) <= top_k)
    return result.sort_values(['flagged', 'anomaly_score'], ascending=False)
