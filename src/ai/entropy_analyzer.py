"""
Entropy analysis — Shannon entropy + block-level visualization.

High entropy (>7.2 bits/byte) indicates encryption or compression.
Block-level analysis reveals partial encryption or embedded encrypted payloads.
"""

import math
from dataclasses import dataclass


@dataclass
class EntropyResult:
    overall:     float          # 0.0 – 8.0 bits/byte
    label:       str            # Human-readable classification
    blocks:      list[float]    # Per-block entropy values
    block_size:  int            # bytes per block
    suspicious:  bool           # True if likely encrypted/packed

    @property
    def percent(self) -> float:
        return self.overall / 8.0 * 100


_LABELS = [
    (7.5, 'Encrypted or compressed (high entropy)'),
    (6.5, 'Packed / compressed binary'),
    (5.5, 'Mixed binary/text'),
    (3.5, 'Normal binary data'),
    (1.5, 'Sparse / mostly zeros'),
    (0.0, 'Uniform / empty data'),
]


def analyze(data: bytes, block_size: int = 4096) -> EntropyResult:
    """Compute Shannon entropy overall and per block."""
    if not data:
        return EntropyResult(0.0, 'Empty', [], block_size, False)
    if block_size <= 0:
        block_size = 4096

    overall = _entropy(data)
    label = _classify(overall)
    suspicious = overall >= 7.2

    blocks = []
    for i in range(0, len(data), block_size):
        chunk = data[i:i + block_size]
        if chunk:
            blocks.append(_entropy(chunk))

    return EntropyResult(
        overall=overall,
        label=label,
        blocks=blocks,
        block_size=block_size,
        suspicious=suspicious,
    )


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(
        (c / n) * math.log2(c / n)
        for c in counts if c
    )


def _classify(e: float) -> str:
    for threshold, label in _LABELS:
        if e >= threshold:
            return label
    return 'Unknown'


def render_html(result: EntropyResult) -> str:
    """Render an inline HTML entropy report with a block heatmap."""
    bar_color = _bar_color(result.overall)
    pct = f'{result.percent:.1f}%'
    suspicious_badge = (
        '<span style="background:#b71c1c;color:#fff;padding:2px 8px;'
        'border-radius:10px;font-size:11px;margin-left:8px">⚠ SUSPICIOUS</span>'
        if result.suspicious else ''
    )

    # Block heatmap (40px × 16px squares, up to 256 blocks shown)
    block_html = ''
    if result.blocks:
        sq_size = 14
        cols = 64
        rows = []
        for i, bv in enumerate(result.blocks[:256]):
            col = _block_color(bv)
            title = f'Block {i}: {bv:.2f} bits/byte'
            rows.append(
                f'<div title="{title}" style="display:inline-block;'
                f'width:{sq_size}px;height:{sq_size}px;background:{col};'
                f'margin:1px"></div>'
            )
        block_html = (
            f'<div style="margin-top:10px"><b style="color:#aaa;font-size:11px">'
            f'Block Entropy Heatmap ({result.block_size//1024}KB blocks — '
            f'green=low, red=high):</b><br>'
            f'<div style="font-size:0;line-height:0;margin-top:4px">'
            + ''.join(rows) +
            '</div></div>'
        )

    return f"""
<div style="background:#16213e;border:1px solid #0f3460;border-radius:6px;padding:12px;margin:8px 0">
  <b style="color:#4ecca3">Entropy Analysis</b>{suspicious_badge}
  <div style="margin:8px 0;font-size:13px">
    <span style="color:#aaa">Overall:</span>
    <span style="color:{bar_color};font-size:20px;font-weight:bold;margin-left:8px">
      {result.overall:.3f} bits/byte</span>
  </div>
  <div style="background:#1a1a2e;border-radius:4px;height:16px;width:100%;overflow:hidden">
    <div style="background:{bar_color};width:{pct};height:100%;transition:width 0.3s"></div>
  </div>
  <div style="color:#aaa;font-size:12px;margin-top:6px">{result.label}</div>
  {block_html}
</div>"""


def _bar_color(e: float) -> str:
    if e >= 7.2: return '#ef5350'
    if e >= 6.0: return '#ffa726'
    if e >= 4.0: return '#ffca28'
    return '#4ecca3'


def _block_color(e: float) -> str:
    # Red at 8, green at 0
    t = e / 8.0
    r = int(t * 239 + (1 - t) * 76)
    g = int((1 - t) * 203 + t * 83)
    b = int((1 - t) * 79 + t * 80)
    return f'rgb({r},{g},{b})'
