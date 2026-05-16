"""
Extract printable strings from binary data — like the Unix `strings` utility,
but also handles UTF-16-LE (Windows) and UTF-32-LE strings.
"""

from dataclasses import dataclass


@dataclass
class StringHit:
    offset:   int
    encoding: str   # 'ascii', 'utf16', 'utf32'
    value:    str


def extract_strings(data: bytes, min_len: int = 6,
                    max_strings: int = 50_000) -> list[StringHit]:
    """
    Extract all printable strings from binary data.
    Returns list sorted by offset.
    """
    results: list[StringHit] = []
    seen: set[str] = set()

    # ASCII / Latin-1 strings
    _extract_ascii(data, min_len, max_strings, results, seen)

    # UTF-16-LE strings (common in Windows binaries)
    _extract_utf16(data, min_len, max_strings // 2, results, seen)

    results.sort(key=lambda x: x.offset)
    return results[:max_strings]


def _extract_ascii(data: bytes, min_len: int, max_n: int,
                   out: list, seen: set) -> None:
    start = -1
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D):
            if start == -1:
                start = i
        else:
            if start != -1:
                length = i - start
                if length >= min_len:
                    s = data[start:i].decode('ascii', errors='replace').strip()
                    if s and s not in seen:
                        seen.add(s)
                        out.append(StringHit(offset=start, encoding='ascii', value=s))
                        if len(out) >= max_n:
                            return
                start = -1
    # Flush trailing
    if start != -1:
        s = data[start:].decode('ascii', errors='replace').strip()
        if len(s) >= min_len and s not in seen:
            seen.add(s)
            out.append(StringHit(offset=start, encoding='ascii', value=s))


def _extract_utf16(data: bytes, min_len: int, max_n: int,
                   out: list, seen: set) -> None:
    start = -1
    i = 0
    n = len(data) - 1
    while i < n:
        lo, hi = data[i], data[i + 1]
        if hi == 0 and (0x20 <= lo < 0x7F or lo in (0x09, 0x0A, 0x0D)):
            if start == -1:
                start = i
            i += 2
        else:
            if start != -1:
                nbytes = i - start
                if nbytes >= min_len * 2:
                    try:
                        s = data[start:i].decode('utf-16-le', errors='replace').strip()
                        if s and s not in seen:
                            seen.add(s)
                            out.append(StringHit(offset=start, encoding='utf16', value=s))
                            if len(out) >= max_n:
                                return
                    except Exception:
                        pass
                start = -1
            i += 1 if hi else 2


def to_html(hits: list[StringHit], max_display: int = 1000) -> str:
    if not hits:
        return '<p style="color:#888">No printable strings found.</p>'

    rows = []
    for h in hits[:max_display]:
        enc_badge = (
            '<span style="background:#1565c0;color:#fff;padding:1px 5px;'
            'border-radius:3px;font-size:10px">UTF-16</span>'
            if h.encoding == 'utf16' else ''
        )
        val = h.value.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        rows.append(
            f'<tr>'
            f'<td style="color:#4ecca3;font-size:11px">{h.offset:08X}</td>'
            f'<td>{enc_badge}</td>'
            f'<td style="font-size:11px;word-break:break-all"><code>{val}</code></td>'
            f'</tr>'
        )

    more = f'<p style="color:#888;font-size:11px">… and {len(hits) - max_display} more</p>' \
           if len(hits) > max_display else ''

    return (
        '<style>table{border-collapse:collapse;width:100%;font-size:12px}'
        'th{background:#0f3460;color:#4ecca3;padding:4px 8px;text-align:left}'
        'td{padding:3px 8px;border-bottom:1px solid #2a2a4a}'
        'tr:hover td{background:#1e1e3a}</style>'
        f'<p style="color:#aaa;font-size:11px">{len(hits)} strings found</p>'
        '<table><tr><th>Offset</th><th>Enc</th><th>String</th></tr>'
        + ''.join(rows) + '</table>' + more
    )
