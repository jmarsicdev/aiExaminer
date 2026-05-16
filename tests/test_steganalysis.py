"""Tests for src/ai/steganalysis.py"""
import io
import unittest

try:
    from PIL import Image
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False

from src.ai.steganalysis import (
    analyze_image, StegResult, StegFinding,
)


def _make_png(width=32, height=32, color=(100, 150, 200)):
    """Return minimal valid PNG bytes."""
    from PIL import Image
    img = Image.new('RGB', (width, height), color=color)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return buf.getvalue()


def _make_jpeg(width=32, height=32, color=(100, 150, 200)):
    """Return minimal valid JPEG bytes."""
    from PIL import Image
    img = Image.new('RGB', (width, height), color=color)
    buf = io.BytesIO()
    img.save(buf, format='JPEG', quality=95)
    return buf.getvalue()


class TestStegResultDataclass(unittest.TestCase):

    def test_is_suspicious_true_when_score_high(self):
        r = StegResult(overall_score=65.0, verdict='Likely Steg')
        self.assertTrue(r.is_suspicious)

    def test_is_suspicious_true_at_40(self):
        r = StegResult(overall_score=40.0, verdict='Suspicious')
        self.assertTrue(r.is_suspicious)

    def test_is_suspicious_false_below_40(self):
        r = StegResult(overall_score=39.9, verdict='Clean')
        self.assertFalse(r.is_suspicious)

    def test_findings_default_empty(self):
        r = StegResult(overall_score=0.0, verdict='Clean')
        self.assertEqual(r.findings, [])


class TestStegFindingDataclass(unittest.TestCase):

    def test_fields_accessible(self):
        f = StegFinding(technique='LSB', score=50.0, detail='Test detail')
        self.assertEqual(f.technique, 'LSB')
        self.assertEqual(f.score, 50.0)
        self.assertEqual(f.detail, 'Test detail')


@unittest.skipUnless(_PIL_AVAILABLE, 'PIL not installed')
class TestAnalyzeImage(unittest.TestCase):

    def test_corrupt_data_returns_none(self):
        result = analyze_image(b'\xff\xd8\xff' + b'\x00' * 10)
        self.assertIsNone(result)

    def test_empty_bytes_returns_none(self):
        result = analyze_image(b'')
        self.assertIsNone(result)

    def test_random_bytes_returns_none(self):
        result = analyze_image(b'\x00' * 100)
        self.assertIsNone(result)

    def test_valid_png_returns_steg_result(self):
        data = _make_png()
        result = analyze_image(data)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, StegResult)

    def test_valid_jpeg_returns_steg_result(self):
        data = _make_jpeg()
        result = analyze_image(data)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, StegResult)

    def test_result_has_overall_score(self):
        data = _make_png()
        result = analyze_image(data)
        self.assertIsNotNone(result)
        self.assertIsInstance(result.overall_score, float)
        self.assertGreaterEqual(result.overall_score, 0.0)
        self.assertLessEqual(result.overall_score, 100.0)

    def test_result_has_verdict(self):
        data = _make_png()
        result = analyze_image(data)
        self.assertIsNotNone(result)
        self.assertIn(result.verdict, ('Clean', 'Suspicious', 'Likely Steg'))

    def test_result_has_findings_list(self):
        data = _make_png()
        result = analyze_image(data)
        self.assertIsNotNone(result)
        self.assertIsInstance(result.findings, list)
        self.assertGreater(len(result.findings), 0)

    def test_findings_are_steg_finding_instances(self):
        data = _make_png()
        result = analyze_image(data)
        self.assertIsNotNone(result)
        for f in result.findings:
            self.assertIsInstance(f, StegFinding)

    def test_jpeg_has_more_findings_than_png(self):
        jpeg = _make_jpeg()
        png = _make_png()
        jpeg_result = analyze_image(jpeg)
        png_result = analyze_image(png)
        self.assertIsNotNone(jpeg_result)
        self.assertIsNotNone(png_result)
        self.assertGreaterEqual(len(jpeg_result.findings), len(png_result.findings))

    def test_uniform_image_clean_verdict(self):
        data = _make_png(color=(128, 128, 128))
        result = analyze_image(data)
        self.assertIsNotNone(result)
        self.assertIn(result.verdict, ('Clean', 'Suspicious', 'Likely Steg'))

    def test_score_is_rounded(self):
        data = _make_png()
        result = analyze_image(data)
        self.assertIsNotNone(result)
        # rounded to 1 decimal place
        self.assertEqual(result.overall_score, round(result.overall_score, 1))


@unittest.skipUnless(_PIL_AVAILABLE, 'PIL not installed')
class TestStegInternalFunctions(unittest.TestCase):
    """Direct tests of private helper functions for branch coverage."""

    def test_lsb_chi_square_too_few_pixels(self):
        from src.ai.steganalysis import _lsb_chi_square
        # < 100 pixels → 'Too few pixels'
        tiny_pixels = [(128, 128, 128)] * 50
        f = _lsb_chi_square(tiny_pixels)
        self.assertIsInstance(f, StegFinding)
        self.assertEqual(f.score, 0.0)

    def test_lsb_chi_square_uniform_distribution_high_score(self):
        from src.ai.steganalysis import _lsb_chi_square
        # Alternating 0/1 LSBs → perfectly uniform → chi²/pair near 0 → score 85
        pixels = [(i % 2, 128, 128) for i in range(500)]
        f = _lsb_chi_square(pixels)
        self.assertIsInstance(f, StegFinding)
        self.assertGreater(f.score, 0.0)

    def test_lsb_chi_square_natural_image_low_score(self):
        from src.ai.steganalysis import _lsb_chi_square
        # Highly non-uniform — all same value → large chi² → low score
        pixels = [(200, 100, 50)] * 200
        f = _lsb_chi_square(pixels)
        self.assertIsInstance(f, StegFinding)

    def test_rs_analysis_small_image(self):
        from src.ai.steganalysis import _rs_analysis
        # < 64 pixels → 'Image too small'
        tiny = [(100, 100, 100)] * 30
        f = _rs_analysis(tiny, 5, 6)
        self.assertEqual(f.score, 0.0)
        self.assertIn('small', f.detail.lower())

    def test_rs_analysis_natural_image(self):
        from src.ai.steganalysis import _rs_analysis
        pixels = [(i % 256, (i * 3) % 256, (i * 7) % 256) for i in range(200)]
        f = _rs_analysis(pixels, 20, 10)
        self.assertIsInstance(f, StegFinding)
        self.assertGreaterEqual(f.score, 0.0)
        self.assertLessEqual(f.score, 100.0)

    def test_jpeg_dct_analysis_normal_jpeg(self):
        from src.ai.steganalysis import _jpeg_dct_analysis
        data = _make_jpeg(width=100, height=100)
        f = _jpeg_dct_analysis(data)
        self.assertIsInstance(f, StegFinding)
        self.assertEqual(f.technique, 'JPEG DCT')

    def test_jpeg_dct_analysis_corrupt_returns_finding(self):
        from src.ai.steganalysis import _jpeg_dct_analysis
        f = _jpeg_dct_analysis(b'\xff\xd8\xff' + b'\x00' * 5)
        self.assertIsInstance(f, StegFinding)
        self.assertEqual(f.score, 0.0)

    def test_is_jpeg_true(self):
        from src.ai.steganalysis import _is_jpeg
        self.assertTrue(_is_jpeg(b'\xFF\xD8\x00'))

    def test_is_jpeg_false_for_png(self):
        from src.ai.steganalysis import _is_jpeg
        self.assertFalse(_is_jpeg(b'\x89PNG'))

    def test_render_html_returns_string(self):
        from src.ai.steganalysis import render_html
        r = StegResult(
            overall_score=50.0,
            verdict='Suspicious',
            findings=[StegFinding('LSB', 50.0, 'test detail')],
        )
        html = render_html(r)
        self.assertIsInstance(html, str)
        self.assertIn('Steganography', html)
        self.assertIn('Suspicious', html)
        self.assertIn('LSB', html)

    def test_render_html_high_score_red(self):
        from src.ai.steganalysis import render_html
        r = StegResult(overall_score=70.0, verdict='Likely Steg',
                       findings=[StegFinding('RS', 70.0, 'high')])
        html = render_html(r)
        self.assertIn('#ef5350', html)

    def test_render_html_medium_score_orange(self):
        from src.ai.steganalysis import render_html
        r = StegResult(overall_score=45.0, verdict='Suspicious',
                       findings=[StegFinding('RS', 45.0, 'medium')])
        html = render_html(r)
        self.assertIn('#ffa726', html)

    def test_render_html_low_score_green(self):
        from src.ai.steganalysis import render_html
        r = StegResult(overall_score=10.0, verdict='Clean',
                       findings=[StegFinding('RS', 10.0, 'clean')])
        html = render_html(r)
        self.assertIn('#4ecca3', html)

    def test_score_color_thresholds(self):
        from src.ai.steganalysis import _score_color
        self.assertEqual(_score_color(65.0), '#ef5350')
        self.assertEqual(_score_color(40.0), '#ffa726')
        self.assertEqual(_score_color(39.9), '#4ecca3')


if __name__ == '__main__':
    unittest.main()
