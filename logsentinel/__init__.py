"""logsentinel: detect suspicious activity in web server access logs.

Combines transparent rule-based detectors with an unsupervised IsolationForest
over per-client behaviour features, then writes alerts and an HTML report.
"""

__version__ = '0.1.0'
