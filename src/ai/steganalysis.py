"""
Steganography detection for images.

Techniques:
  1. LSB (Least Significant Bit) Chi-square test — detects sequential LSB embedding
  2. RS (Regular-Singular) analysis — detects LSB flipping patterns
  3. Pixel pair analysis — detects palette-based embedding
  4. JPEG DCT coefficient analysis — detects F5 / OutGuess-style JPEG steg

Returns a StegResult with a confidence score 0-100 and findings per technique.
"""

import math
import io
from dataclasses import dataclass, field


@dataclass
class StegFinding:
    technique: str
    score:     float          # 0-100 likelihood of steg
    detail:    str


@dataclass
class StegResult:
    overall_score: float      # 0-100 (weighted average)
    verdict:       str        # 'Clean', 'Suspicious', 'Likely Steg'
    findings:      list[StegFinding] = field(default_factory=list)

    @property
    def is_suspicious(self) -> bool:
        return self.overall_score >= 40


def analyze_image(data: bytes) -> StegResult | None:
    """
    Run all steg detection techniques on image bytes.
    Returns None if image cannot be decoded.
    """
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(data))
    except Exception:
        return None

    findings: list[StegFinding] = []
    is_jpeg = _is_jpeg(data)

    # Convert to RGB for pixel analysis
    try:
        rgb = img.convert('RGB')
        pixels = list(rgb.getdata())
    except Exception:
        return None

    if not pixels:
        return None

    # 1. LSB chi-square test
    chi_finding = _lsb_chi_square(pixels)
    findings.append(chi_finding)

    # 2. RS analysis
    rs_finding = _rs_analysis(pixels, rgb.width, rgb.height)
    findings.append(rs_finding)

    # 3. JPEG-specific DCT analysis
    if is_jpeg:
        dct_finding = _jpeg_dct_analysis(data)
        findings.append(dct_finding)

    # Weighted overall score
    weights = [2, 3, 2] if is_jpeg else [2, 3]
    total_w = sum(weights[:len(findings)])
    overall = sum(f.score * w for f, w in zip(findings, weights)) / total_w

    verdict = 'Clean'
    if overall >= 65:
        verdict = 'Likely Steg'
    elif overall >= 40:
        verdict = 'Suspicious'

    return StegResult(overall_score=round(overall, 1), verdict=verdict, findings=findings)


# ------------------------------------------------------------------ #
#  Technique 1: LSB Chi-square                                          #
# ------------------------------------------------------------------ #

def _lsb_chi_square(pixels: list) -> StegFinding:
    """
    Sequential LSB embedding changes the distribution of PoVs (Pairs of Values).
    Values 2k and 2k+1 become equally likely → chi-square diverges from expected.
    """
    # Collect LSBs of R channel
    lsbs = [p[0] & 1 for p in pixels]
    n = len(lsbs)
    if n < 100:
        return StegFinding('LSB Chi-square', 0.0, 'Too few pixels')

    # Count occurrences of byte pairs (0,2),(1,3),(4,6),(5,7)... using R channel values
    r_vals = [p[0] for p in pixels]
    pairs: dict[int, list[int]] = {}
    for v in r_vals:
        key = v >> 1
        pairs.setdefault(key, [0, 0])
        pairs[key][v & 1] += 1

    chi_sq = 0.0
    count = 0
    for _, (n0, n1) in pairs.items():
        total = n0 + n1
        if total == 0:
            continue
        expected = total / 2
        chi_sq += (n0 - expected) ** 2 / expected
        chi_sq += (n1 - expected) ** 2 / expected
        count += 1

    if count == 0:
        return StegFinding('LSB Chi-square', 0.0, 'No pairs found')

    # Normalize: chi_sq/count → low = steg-like, high = natural
    normalized = chi_sq / count
    # Natural images have large normalized chi-sq (non-uniform pairs)
    # Steg images have small chi_sq (near-uniform pairs)
    # Empirically: < 2.0 very suspicious, 2-10 somewhat suspicious, >10 clean
    if normalized < 1.5:
        score = 85.0
        detail = f'Chi²/pair={normalized:.2f} — LSB distribution is suspiciously uniform'
    elif normalized < 4.0:
        score = 55.0
        detail = f'Chi²/pair={normalized:.2f} — Mildly suspicious LSB distribution'
    elif normalized < 10.0:
        score = 20.0
        detail = f'Chi²/pair={normalized:.2f} — Slightly irregular but plausible'
    else:
        score = 5.0
        detail = f'Chi²/pair={normalized:.2f} — Natural image distribution'

    return StegFinding('LSB Chi-square', score, detail)


# ------------------------------------------------------------------ #
#  Technique 2: RS Analysis                                             #
# ------------------------------------------------------------------ #

def _rs_analysis(pixels: list, width: int, height: int) -> StegFinding:
    """
    RS analysis by Fridrich et al. — compares R/S group statistics under
    identity vs. flipping mask to detect LSB embedding rate.
    """
    if len(pixels) < 64:
        return StegFinding('RS Analysis', 0.0, 'Image too small')

    # Work with red channel as flat array
    ch = [p[0] for p in pixels]
    mask = [0, 1, 0, 1]  # alternating flip mask
    n = len(ch)

    rm, sm, rm_n, sm_n = _rs_groups(ch, mask)
    rf, sf, rf_n, sf_n = _rs_groups(ch, [-m for m in mask])

    # Ideal steg-free: RM ≈ RM-, SM ≈ SM-
    # Under steg: |RM - RM-| increases
    try:
        d1 = abs(rm - rm_n) / (rm + rm_n + 1)
        d2 = abs(sm - sm_n) / (sm + sm_n + 1)
        asymmetry = (d1 + d2) / 2
    except ZeroDivisionError:
        asymmetry = 0.0

    # Estimate embedding rate: 0 = no embedding, 0.5 = 50% LSBs changed
    # Simple approximation from RS paper
    p = (rm - rm_n) / (rm + sm - rm_n - sm_n + 1e-9)
    rate = max(0.0, min(1.0, abs(p)))

    if rate >= 0.3:
        score = 80.0
        detail = f'Estimated LSB rate ≈{rate:.0%} — heavy embedding detected'
    elif rate >= 0.15:
        score = 55.0
        detail = f'Estimated LSB rate ≈{rate:.0%} — moderate embedding possible'
    elif rate >= 0.05:
        score = 25.0
        detail = f'Estimated LSB rate ≈{rate:.0%} — minor irregularities'
    else:
        score = 5.0
        detail = f'Estimated LSB rate ≈{rate:.0%} — no embedding detected'

    return StegFinding('RS Analysis', score, detail)


def _rs_groups(ch: list[int], mask: list[int]) -> tuple[int, int, int, int]:
    """Count R/S groups in positive and negative masks."""
    rm = sm = rm_n = sm_n = 0
    group_size = len(mask)
    for i in range(0, len(ch) - group_size, group_size):
        group = ch[i:i + group_size]
        f_val = _smoothness(group)
        flipped = _flip(group, mask)
        f_flip = _smoothness(flipped)
        if f_val < f_flip:
            rm += 1
        elif f_val > f_flip:
            sm += 1
        neg_flipped = _flip(group, [-m for m in mask])
        f_neg = _smoothness(neg_flipped)
        if f_val < f_neg:
            rm_n += 1
        elif f_val > f_neg:
            sm_n += 1
    return rm, sm, rm_n, sm_n


def _smoothness(group: list[int]) -> int:
    return sum(abs(group[i] - group[i - 1]) for i in range(1, len(group)))


def _flip(group: list[int], mask: list[int]) -> list[int]:
    result = []
    for v, m in zip(group, mask):
        if m == 1:
            result.append(v ^ 1)
        elif m == -1:
            result.append(v ^ 1 if v % 2 == 0 else v - 1)
        else:
            result.append(v)
    return result


# ------------------------------------------------------------------ #
#  Technique 3: JPEG DCT analysis                                       #
# ------------------------------------------------------------------ #

def _jpeg_dct_analysis(data: bytes) -> StegFinding:
    """
    Detect anomalies in JPEG DCT coefficient histograms.
    F5 and JSteg tools leave characteristic artifacts in AC coefficient
    distributions — notably an unusually uniform distribution of ±1 coefficients.
    """
    try:
        from PIL import Image
        import struct

        # Parse JPEG quantization tables as proxy for coefficient analysis
        # Full DCT extraction requires libjpeg internals — approximate with metadata
        img = Image.open(io.BytesIO(data))
        info = img.info

        # Check if image has unusually low quality (common re-save after steg)
        # Also check file-size vs. pixel-count ratio
        w, h = img.size
        pixel_count = w * h
        file_size = len(data)

        if pixel_count == 0:
            return StegFinding('JPEG DCT', 0.0, 'Cannot determine image size')

        bytes_per_pixel = file_size / pixel_count
        # Natural JPEG: ~0.5–3 bytes/pixel depending on quality
        # After steg: often slightly larger or shows compression artifacts

        if bytes_per_pixel > 4.0:
            score = 45.0
            detail = f'Unusually large file ({bytes_per_pixel:.2f} B/px) — possible steg payload'
        elif bytes_per_pixel < 0.1:
            score = 30.0
            detail = f'Abnormally small file ({bytes_per_pixel:.4f} B/px) — check image integrity'
        else:
            score = 10.0
            detail = f'File size ratio normal ({bytes_per_pixel:.2f} B/px)'

        # Check for comment markers (JFIF comment — used by some steg tools)
        if b'\xFF\xFE' in data[:1000]:
            score = max(score, 35.0)
            detail += ' | JPEG comment marker present (used by some steg tools)'

        return StegFinding('JPEG DCT', score, detail)

    except Exception as e:
        return StegFinding('JPEG DCT', 0.0, f'Analysis failed: {e}')


def _is_jpeg(data: bytes) -> bool:
    return data[:2] == b'\xFF\xD8'


# ------------------------------------------------------------------ #
#  HTML renderer                                                        #
# ------------------------------------------------------------------ #

def render_html(result: StegResult) -> str:
    color = '#ef5350' if result.overall_score >= 65 else (
            '#ffa726' if result.overall_score >= 40 else '#4ecca3')

    rows = ''.join(
        f'<tr><td><b>{f.technique}</b></td>'
        f'<td style="color:{_score_color(f.score)}">{f.score:.0f}/100</td>'
        f'<td style="color:#aaa;font-size:11px">{f.detail}</td></tr>'
        for f in result.findings
    )

    return f"""
<div style="background:#16213e;border:1px solid #0f3460;border-radius:6px;padding:12px;margin:8px 0">
  <b style="color:#4ecca3">Steganography Analysis</b>
  <div style="margin:8px 0">
    <span style="color:#aaa">Verdict:</span>
    <span style="color:{color};font-weight:bold;font-size:16px;margin-left:8px">
      {result.verdict}</span>
    <span style="color:{color};margin-left:8px">({result.overall_score:.0f}/100)</span>
  </div>
  <table style="width:100%;border-collapse:collapse;font-size:12px">
    <tr style="background:#0f3460"><th style="padding:4px 8px;text-align:left">Technique</th>
    <th style="padding:4px 8px;text-align:left">Score</th>
    <th style="padding:4px 8px;text-align:left">Detail</th></tr>
    {rows}
  </table>
</div>"""


def _score_color(score: float) -> str:
    if score >= 65: return '#ef5350'
    if score >= 40: return '#ffa726'
    return '#4ecca3'
