"""
IOC / Entity extraction using compiled regex patterns.
Instant — no model loading. Covers 15 forensically relevant entity kinds.
"""

import re
from dataclasses import dataclass


@dataclass
class Entity:
    kind:    str
    value:   str
    context: str  # ~60-char surrounding snippet


# ------------------------------------------------------------------ #
#  Compiled patterns (module-level for zero-cost reuse)                #
# ------------------------------------------------------------------ #

_P = {
    'Email': re.compile(
        r'\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,}\b',
        re.MULTILINE
    ),
    'IPv4': re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
        r'(?::\d{1,5})?\b',
        re.MULTILINE
    ),
    'IPv6': re.compile(
        r'(?<![:\w])(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?![:\w])',
        re.MULTILINE
    ),
    'URL': re.compile(
        r'(?:https?|ftp)://[^\s<>\'"(){}\[\]]{4,}',
        re.MULTILINE | re.IGNORECASE
    ),
    'Domain': re.compile(
        r'\b(?<!@)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
        r'(?:com|net|org|gov|edu|mil|io|co|uk|de|ru|cn|onion)\b',
        re.MULTILINE | re.IGNORECASE
    ),
    'Phone (US)': re.compile(
        r'\b(?:\+?1[-.\s]?)?\(?([2-9]\d{2})\)?[-.\s]?([2-9]\d{2})[-.\s]?(\d{4})\b',
        re.MULTILINE
    ),
    'SSN': re.compile(
        r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b',
        re.MULTILINE
    ),
    'Credit Card': re.compile(
        r'\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})(?:[-\s]?\d{4}){3}\b',
        re.MULTILINE
    ),
    'Bitcoin': re.compile(
        r'\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b',
        re.MULTILINE
    ),
    'Ethereum': re.compile(
        r'\b0x[a-fA-F0-9]{40}\b',
        re.MULTILINE
    ),
    'MAC Address': re.compile(
        r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b',
        re.MULTILINE
    ),
    'GUID / UUID': re.compile(
        r'\{?[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\}?',
        re.MULTILINE
    ),
    'Windows Path': re.compile(
        r'[A-Za-z]:\\(?:[^\\\/:*?"<>|\r\n\t]{1,255}\\)*[^\\\/:*?"<>|\r\n\t]{0,255}',
        re.MULTILINE
    ),
    'Registry Key': re.compile(
        r'(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)'
        r'|HKLM|HKCU|HKCR|HKU|HKCC)(?:\\[^\\\r\n"\']{1,255})+',
        re.MULTILINE | re.IGNORECASE
    ),
    'Base64 Blob': re.compile(
        r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
        re.MULTILINE
    ),
}

# Entities to skip when value matches these (reduce noise)
_SKIP_DOMAINS = {
    'example.com', 'schema.org', 'w3.org', 'microsoft.com',
    'apple.com', 'google.com', 'github.com',
}


class EntityExtractor:
    """Stateless regex-based IOC extractor."""

    def extract(self, text: str, max_per_kind: int = 500) -> list[Entity]:
        """Run all patterns against text; deduplicate by (kind, value)."""
        results: list[Entity] = []
        seen: set[tuple[str, str]] = set()

        for kind, pattern in _P.items():
            count = 0
            for m in pattern.finditer(text):
                if count >= max_per_kind:
                    break
                value = m.group(0).strip()
                if not value:
                    continue
                # Noise filters
                if kind == 'Domain' and value.lower() in _SKIP_DOMAINS:
                    continue
                if kind == 'Base64 Blob' and len(value) < 40:
                    continue

                key = (kind, value)
                if key in seen:
                    continue
                seen.add(key)

                start = max(0, m.start() - 30)
                end   = min(len(text), m.end() + 30)
                ctx   = text[start:end].replace('\n', ' ').replace('\r', '')
                results.append(Entity(kind=kind, value=value, context=ctx))
                count += 1

        return results

    def extract_from_bytes(self, data: bytes,
                           max_bytes: int = 512 * 1024) -> list[Entity]:
        """Try multiple encodings; merge unique results."""
        chunk = data[:max_bytes]
        all_results: list[Entity] = []
        seen: set[tuple[str, str]] = set()

        for enc in ('utf-8', 'utf-16-le', 'latin-1'):
            try:
                text = chunk.decode(enc, errors='ignore')
            except Exception:
                continue
            for e in self.extract(text):
                key = (e.kind, e.value)
                if key not in seen:
                    seen.add(key)
                    all_results.append(e)

        return all_results

    def to_html(self, entities: list[Entity]) -> str:
        """Render a compact HTML summary for the AI Analysis tab."""
        if not entities:
            return '<p style="color:#888">No IOCs or entities detected.</p>'

        by_kind: dict[str, list[Entity]] = {}
        for e in entities:
            by_kind.setdefault(e.kind, []).append(e)

        _colors = {
            'Email': '#4A9EFF', 'IPv4': '#FF7043', 'IPv6': '#FF7043',
            'URL': '#66BB6A',   'Domain': '#26C6DA', 'Phone (US)': '#AB47BC',
            'SSN': '#EF5350',   'Credit Card': '#EF5350', 'Bitcoin': '#FFA726',
            'Ethereum': '#FFA726', 'MAC Address': '#8D6E63', 'GUID / UUID': '#78909C',
            'Windows Path': '#FFCA28', 'Registry Key': '#FF7043',
            'Base64 Blob': '#EC407A',
        }

        parts = ['<style>'
                 'table{border-collapse:collapse;width:100%;font-size:12px}'
                 'th{background:#2a2a2a;color:#ccc;padding:4px 8px;text-align:left}'
                 'td{padding:3px 8px;border-bottom:1px solid #333;word-break:break-all}'
                 '.kind-badge{display:inline-block;padding:1px 6px;border-radius:3px;'
                 'color:#111;font-weight:bold;font-size:11px}'
                 '.ctx{color:#777;font-size:11px}'
                 '</style>']

        for kind, items in sorted(by_kind.items(), key=lambda x: -len(x[1])):
            color = _colors.get(kind, '#90A4AE')
            parts.append(
                f'<p><span class="kind-badge" style="background:{color}">'
                f'{kind}</span> &nbsp;<b>{len(items)}</b> unique</p>'
                f'<table><tr><th>Value</th><th>Context</th></tr>'
            )
            for ent in items[:100]:
                ctx = ent.context.replace('<', '&lt;').replace('>', '&gt;')
                val = ent.value.replace('<', '&lt;').replace('>', '&gt;')
                parts.append(
                    f'<tr><td><code>{val}</code></td>'
                    f'<td class="ctx">{ctx}</td></tr>'
                )
            if len(items) > 100:
                parts.append(f'<tr><td colspan="2" class="ctx">… and {len(items)-100} more</td></tr>')
            parts.append('</table><br>')

        return ''.join(parts)

    def summary(self, entities: list[Entity]) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in entities:
            out[e.kind] = out.get(e.kind, 0) + 1
        return out
