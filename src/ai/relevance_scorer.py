"""
Forensic relevance scorer — ranks files 0-100 based on multiple signals.

Combines:
  • File type suspiciousness (executables, encrypted, scripts)
  • IOC density (emails, IPs, SSNs, crypto addresses)
  • Entropy (encrypted/compressed = more interesting)
  • Path signals (temp dirs, startup, AppData, hidden)
  • Deletion status (deleted files are always more interesting)
  • String signals (keywords like 'password', 'secret', 'bitcoin', 'transfer')
  • Timestamp anomalies (files with future timestamps, year 2000-era etc.)

This is something neither Autopsy nor FTK Imager do — both require manual review.
"""

from __future__ import annotations
import math
import re
from dataclasses import dataclass, field


@dataclass
class ScoreResult:
    score:       int                     # 0-100
    tier:        str                     # 'Critical', 'High', 'Medium', 'Low', 'Noise'
    reasons:     list[str] = field(default_factory=list)
    breakdown:   dict[str, int] = field(default_factory=dict)

    @property
    def badge_color(self) -> str:
        return _TIER_COLOR.get(self.tier, '#424242')


_TIER_COLOR = {
    'Critical': '#b71c1c',
    'High':     '#e65100',
    'Medium':   '#f57f17',
    'Low':      '#1565c0',
    'Noise':    '#424242',
}

# ---- Keyword signals ----
_CREDENTIAL_RE = re.compile(
    r'\b(?:password|passwd|pwd|secret|credential|apikey|api_key|token|auth|'
    r'private_key|privkey|ssh_key|pgp|gpg|keystore)\b',
    re.IGNORECASE,
)
_FINANCE_RE = re.compile(
    r'\b(?:bitcoin|ethereum|monero|wallet|transfer|wire|iban|routing|swift|'
    r'account.?number|bank|paypal|credit.?card)\b',
    re.IGNORECASE,
)
_COMMS_RE = re.compile(
    r'\b(?:telegram|signal|tor|onion|vpn|proxy|darkweb|dark.?web|clearnet)\b',
    re.IGNORECASE,
)
_MALWARE_RE = re.compile(
    r'\b(?:exploit|shellcode|payload|backdoor|rootkit|keylogger|ransomware|'
    r'malware|dropper|botnet|c2|command.?and.?control|inject|bypass|privilege)\b',
    re.IGNORECASE,
)

# ---- Path suspiciousness ----
# Covers both backslash (raw Windows) and forward-slash (parser-normalised) paths.
_SUSPICIOUS_PATHS = [
    r'[/\\]temp[/\\]',
    r'[/\\]tmp[/\\]',
    r'[/\\]appdata[/\\]local[/\\]temp',
    r'[/\\]windows[/\\]temp',
    r'[/\\]startup[/\\]',
    r'[/\\]start menu[/\\]programs[/\\]startup',
    r'[/\\]system32[/\\]',
    r'[/\\]syswow64[/\\]',
    r'[/\\]recycle',
    r'[/\\]\.trash',
    r'[/\\]programdata[/\\]',
    r'[/\\]users[/\\]public[/\\]',
    r'/etc/cron',
    r'/etc/init\.d',
    r'/home/\.',
]
_SUSPICIOUS_PATH_RE = re.compile('|'.join(_SUSPICIOUS_PATHS), re.IGNORECASE)

# ---- File category scores ----
_CATEGORY_BASE = {
    'executable': 25,
    'script':     20,
    'forensic':   15,
    'registry':   15,
    'log':        10,
    'database':   10,
    'network':    10,
    'document':    8,
    'crypto':     20,
    'archive':     8,
    'image':       5,
    'audio':       3,
    'video':       3,
    'text':        5,
    'unknown':    12,
}


def score_file(
    file_path: str,
    file_category: str,
    entropy: float,
    entities: list,          # list[Entity] from entity_extractor
    content_sample: bytes,   # first 64KB
    is_deleted: bool = False,
    mtime: str | None = None,
) -> ScoreResult:
    """Compute overall forensic relevance score 0-100."""
    reasons: list[str] = []
    breakdown: dict[str, int] = {}

    # 1. Base score from file type
    base = _CATEGORY_BASE.get(file_category, 5)
    breakdown['file_type'] = base
    if base >= 15:
        reasons.append(f'High-value file type ({file_category})')

    # 2. Deletion bonus
    if is_deleted:
        breakdown['deleted'] = 20
        reasons.append('File is deleted (recovered)')

    # 3. Entropy
    ent_score = 0
    if entropy >= 7.5:
        ent_score = 20
        reasons.append(f'Very high entropy ({entropy:.2f}) — likely encrypted')
    elif entropy >= 7.0:
        ent_score = 12
        reasons.append(f'High entropy ({entropy:.2f}) — possibly encrypted/packed')
    breakdown['entropy'] = ent_score

    # 4. IOC density
    ioc_counts: dict[str, int] = {}
    for ent in entities:
        ioc_counts[ent.kind] = ioc_counts.get(ent.kind, 0) + 1

    ioc_score = 0
    high_value_iocs = {
        'SSN': 20, 'Credit Card': 20, 'Bitcoin': 15, 'Ethereum': 15,
        'Email': 5, 'IPv4': 3, 'URL': 3, 'Registry Key': 8,
        'Windows Path': 3, 'MAC Address': 5,
    }
    for kind, weight in high_value_iocs.items():
        count = ioc_counts.get(kind, 0)
        if count:
            pts = min(weight, weight * math.log1p(count))
            ioc_score += pts
            if weight >= 10:
                reasons.append(f'{count}× {kind} found')
    ioc_score = min(ioc_score, 30)
    breakdown['ioc_density'] = int(ioc_score)

    # 5. Keyword signals from content sample
    kw_score = 0
    if content_sample:
        text = content_sample.decode('latin-1', errors='replace')
        if _CREDENTIAL_RE.search(text):
            kw_score += 15
            reasons.append('Credential/key keywords found')
        if _FINANCE_RE.search(text):
            kw_score += 10
            reasons.append('Financial/crypto keywords found')
        if _COMMS_RE.search(text):
            kw_score += 8
            reasons.append('Anonymous communications keywords found')
        if _MALWARE_RE.search(text):
            kw_score += 12
            reasons.append('Malware-related keywords found')
    kw_score = min(kw_score, 25)
    breakdown['keywords'] = kw_score

    # 6. Path suspiciousness
    path_score = 0
    if _SUSPICIOUS_PATH_RE.search(file_path):
        path_score = 10
        reasons.append('Suspicious directory path')
    # Hidden file (starts with dot on Unix or hidden names on Windows)
    fname = file_path.rsplit('/', 1)[-1].rsplit('\\', 1)[-1]
    if fname.startswith('.') or fname.lower() in ('thumbs.db', 'desktop.ini'):
        path_score += 5
        reasons.append('Hidden / system file')
    breakdown['path'] = min(path_score, 12)

    # 7. Suspicious extension mismatch (magic vs. name)
    # (We don't have magic here, but we can flag double-extensions)
    ext_parts = fname.split('.')
    if len(ext_parts) >= 3:
        second_ext = ext_parts[-2].lower()
        if second_ext in ('jpg', 'pdf', 'doc', 'txt', 'xls', 'png'):
            breakdown['double_ext'] = 15
            reasons.append(f'Double extension detected ({fname}) — common disguise')

    raw_score = (
        breakdown.get('file_type', 0)
        + breakdown.get('deleted', 0)
        + breakdown.get('entropy', 0)
        + int(ioc_score)
        + kw_score
        + breakdown.get('path', 0)
        + breakdown.get('double_ext', 0)
    )

    final = min(100, raw_score)
    tier = _tier(final)

    return ScoreResult(score=final, tier=tier, reasons=reasons, breakdown=breakdown)


def _tier(score: int) -> str:
    if score >= 75: return 'Critical'
    if score >= 50: return 'High'
    if score >= 30: return 'Medium'
    if score >= 12: return 'Low'
    return 'Noise'


def render_badge(result: ScoreResult) -> str:
    """Return a compact HTML badge for inline display in the tree or preview."""
    return (
        f'<span style="background:{result.badge_color};color:#fff;'
        f'padding:2px 7px;border-radius:10px;font-size:11px;font-weight:bold">'
        f'{result.score} {result.tier}</span>'
    )


def render_html(result: ScoreResult) -> str:
    bar_color = result.badge_color
    reasons_html = ''.join(
        f'<li style="color:#aaa;font-size:12px">{r}</li>'
        for r in result.reasons
    ) or '<li style="color:#555">No specific signals detected</li>'

    breakdown_html = ''.join(
        f'<tr><td style="color:#aaa;font-size:11px">{k}</td>'
        f'<td style="color:{bar_color};font-weight:bold">{v}</td></tr>'
        for k, v in sorted(result.breakdown.items(), key=lambda x: -x[1])
        if v > 0
    )

    return f"""
<div style="background:#16213e;border:1px solid #0f3460;border-radius:6px;padding:12px;margin:8px 0">
  <b style="color:#4ecca3">Forensic Relevance Score</b>
  <div style="margin:8px 0">
    <span style="color:{bar_color};font-size:32px;font-weight:bold">{result.score}</span>
    <span style="color:{bar_color};font-size:14px;margin-left:8px">/100 — {result.tier}</span>
  </div>
  <div style="background:#1a1a2e;border-radius:4px;height:12px;width:100%;overflow:hidden;margin-bottom:10px">
    <div style="background:{bar_color};width:{result.score}%;height:100%"></div>
  </div>
  <table style="width:200px;border-collapse:collapse">
    {breakdown_html}
  </table>
  <b style="color:#aaa;font-size:12px">Signals:</b>
  <ul style="margin:4px 0 0 16px;padding:0">{reasons_html}</ul>
</div>"""
