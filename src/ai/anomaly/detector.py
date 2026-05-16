"""
Log anomaly detector — uses IsolationForest with richer feature engineering.
Also handles structured log formats (Windows Event Log CSV, Apache/NGINX access logs).
"""

import re
import math
from dataclasses import dataclass, field

try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    _SKLEARN_OK = True
except ImportError:
    _SKLEARN_OK = False


@dataclass
class AnomalyResult:
    total_lines:   int
    anomaly_lines: list[str] = field(default_factory=list)
    error_lines:   list[str] = field(default_factory=list)
    stats:         dict      = field(default_factory=dict)
    summary_html:  str       = ''


# ---- Pattern matchers for log parsing ----
_HTTP_STATUS_RE = re.compile(r'\b([1-5]\d{2})\b')
_TIMESTAMP_RE   = re.compile(
    r'\b\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}\b|'
    r'\b\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\b'
)
_IP_RE          = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_ERROR_WORDS    = re.compile(
    r'\b(?:error|fail|critical|exception|denied|refused|timeout|crash|'
    r'invalid|corrupt|unauthori[sz]ed|forbidden|attack|inject|overflow)\b',
    re.IGNORECASE,
)
_SIZE_RE        = re.compile(r'\b(\d+)\b')


class LogAnomalyDetector:
    def __init__(self):
        if _SKLEARN_OK:
            self._model = IsolationForest(contamination=0.08, random_state=42,
                                          n_estimators=100)
        else:
            self._model = None

    def analyze_logs(self, log_content: str) -> str:
        if not log_content or not log_content.strip():
            return 'No log content to analyze.'

        result = self._analyze(log_content)
        return _render_text(result)

    def analyze_logs_html(self, log_content: str) -> str:
        if not log_content or not log_content.strip():
            return '<p style="color:#888">No log content to analyze.</p>'
        result = self._analyze(log_content)
        return _render_html(result)

    def _analyze(self, content: str) -> AnomalyResult:
        lines = content.splitlines()
        lines = [l for l in lines if l.strip()]
        result = AnomalyResult(total_lines=len(lines))

        if len(lines) < 3:
            result.stats['note'] = 'Too few lines for statistical analysis'
            return result

        # Feature extraction
        features = [_extract_features(l) for l in lines]

        # Error/keyword detection (always, regardless of ML)
        for i, line in enumerate(lines):
            if _ERROR_WORDS.search(line):
                result.error_lines.append(line)

        # ML-based anomaly detection
        if self._model is not None and _SKLEARN_OK:
            np_feat = np.array(features, dtype=float)
            preds = self._model.fit_predict(np_feat)
            result.anomaly_lines = [lines[i] for i, p in enumerate(preds) if p == -1]
        else:
            # Fallback: statistical outlier detection via IQR
            lengths = [f[0] for f in features]
            q1, q3 = _percentile(lengths, 25), _percentile(lengths, 75)
            iqr = q3 - q1
            hi = q3 + 3 * iqr
            lo = max(0, q1 - 3 * iqr)
            result.anomaly_lines = [
                lines[i] for i, f in enumerate(features)
                if not (lo <= f[0] <= hi)
            ]

        # Status code distribution
        status_counts: dict[str, int] = {}
        for line in lines:
            for m in _HTTP_STATUS_RE.finditer(line):
                sc = m.group(1)
                status_counts[sc] = status_counts.get(sc, 0) + 1

        result.stats = {
            'total':     len(lines),
            'anomalies': len(result.anomaly_lines),
            'errors':    len(result.error_lines),
            'http_status': status_counts,
        }
        return result


def _extract_features(line: str) -> list[float]:
    """Richer feature vector for log line anomaly detection."""
    length     = len(line)
    word_count = len(line.split())
    digit_r    = sum(c.isdigit() for c in line) / max(length, 1)
    upper_r    = sum(c.isupper() for c in line) / max(length, 1)
    space_r    = sum(c == ' ' for c in line) / max(length, 1)
    has_ip     = 1.0 if _IP_RE.search(line) else 0.0
    has_error  = 1.0 if _ERROR_WORDS.search(line) else 0.0
    has_ts     = 1.0 if _TIMESTAMP_RE.search(line) else 0.0
    # Largest numeric token (size, port, etc.)
    nums = [int(m) for m in _SIZE_RE.findall(line) if int(m) < 10**9]
    max_num = math.log1p(max(nums)) if nums else 0.0
    return [length, word_count, digit_r, upper_r, space_r,
            has_ip, has_error, has_ts, max_num]


def _percentile(data: list, pct: float) -> float:
    s = sorted(data)
    k = (len(s) - 1) * pct / 100
    f = int(k)
    c = f + 1 if f + 1 < len(s) else f
    return s[f] + (k - f) * (s[c] - s[f])


def _render_text(r: AnomalyResult) -> str:
    out = '--- AI LOG ANOMALY ANALYSIS ---\n'
    out += f'Lines analyzed: {r.total_lines}\n'
    out += f'Anomalies (ML):  {len(r.anomaly_lines)}\n'
    out += f'Error keywords:  {len(r.error_lines)}\n\n'

    if r.anomaly_lines:
        out += 'TOP ANOMALOUS LINES:\n'
        for i, line in enumerate(r.anomaly_lines[:10]):
            out += f'  {i+1}. {line[:120]}{"…" if len(line) > 120 else ""}\n'
        if len(r.anomaly_lines) > 10:
            out += f'  … and {len(r.anomaly_lines) - 10} more\n'

    if r.stats.get('http_status'):
        out += '\nHTTP STATUS CODES:\n'
        for code, cnt in sorted(r.stats['http_status'].items()):
            out += f'  {code}: {cnt}\n'
    return out


def _render_html(r: AnomalyResult) -> str:
    def row(line, color='#ef5350'):
        l = line.replace('<', '&lt;').replace('>', '&gt;')
        return (f'<div style="background:#1a1a2e;border-left:3px solid {color};'
                f'padding:3px 8px;margin:2px 0;font-size:11px;font-family:monospace">{l}</div>')

    sc_html = ''
    if r.stats.get('http_status'):
        sc_rows = ''.join(
            f'<span style="background:#0f3460;color:#4ecca3;padding:2px 6px;'
            f'border-radius:3px;margin:2px;font-size:11px">{code}: {cnt}</span>'
            for code, cnt in sorted(r.stats['http_status'].items())
        )
        sc_html = f'<div style="margin:8px 0"><b style="color:#aaa">HTTP Status Codes:</b><br>{sc_rows}</div>'

    anom_html = ''.join(row(l) for l in r.anomaly_lines[:20])
    err_html  = ''.join(row(l, '#ffa726') for l in r.error_lines[:20])

    return f"""
<div style="background:#16213e;border:1px solid #0f3460;border-radius:6px;padding:12px">
  <b style="color:#4ecca3">Log Anomaly Analysis</b>
  <div style="display:flex;gap:20px;margin:8px 0;font-size:12px">
    <span><b style="color:#e0e0e0">{r.total_lines}</b><span style="color:#aaa"> lines</span></span>
    <span><b style="color:#ef5350">{len(r.anomaly_lines)}</b><span style="color:#aaa"> anomalies</span></span>
    <span><b style="color:#ffa726">{len(r.error_lines)}</b><span style="color:#aaa"> error keywords</span></span>
  </div>
  {sc_html}
  {'<b style="color:#ef5350;font-size:12px">Anomalous Lines:</b>' + anom_html if anom_html else ''}
  {'<b style="color:#ffa726;font-size:12px">Error Keyword Lines:</b>' + err_html if err_html else ''}
</div>"""
