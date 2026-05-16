"""Tests for src/ai/entropy_analyzer.py"""
import math
import unittest

from src.ai.entropy_analyzer import (
    EntropyResult, analyze, render_html, _entropy, _classify,
    _bar_color, _block_color,
)


class TestEntropyResult(unittest.TestCase):

    def test_percent_property(self):
        r = EntropyResult(overall=4.0, label='x', blocks=[], block_size=4096, suspicious=False)
        self.assertAlmostEqual(r.percent, 50.0)

    def test_percent_zero(self):
        r = EntropyResult(overall=0.0, label='x', blocks=[], block_size=4096, suspicious=False)
        self.assertEqual(r.percent, 0.0)

    def test_percent_max(self):
        r = EntropyResult(overall=8.0, label='x', blocks=[], block_size=4096, suspicious=False)
        self.assertAlmostEqual(r.percent, 100.0)


class TestAnalyze(unittest.TestCase):

    def test_empty_data_returns_zero(self):
        r = analyze(b'')
        self.assertEqual(r.overall, 0.0)
        self.assertEqual(r.label, 'Empty')
        self.assertFalse(r.suspicious)
        self.assertEqual(r.blocks, [])

    def test_uniform_data_low_entropy(self):
        r = analyze(b'\x00' * 1000)
        self.assertAlmostEqual(r.overall, 0.0, places=5)
        self.assertFalse(r.suspicious)

    def test_high_entropy_flagged_suspicious(self):
        import os
        data = os.urandom(8192)
        r = analyze(data)
        self.assertGreater(r.overall, 6.0)
        if r.overall >= 7.2:
            self.assertTrue(r.suspicious)

    def test_text_data_moderate_entropy(self):
        data = b'Hello, world! This is a normal text string. ' * 100
        r = analyze(data)
        self.assertGreater(r.overall, 0.0)
        self.assertLess(r.overall, 7.2)
        self.assertFalse(r.suspicious)

    def test_block_size_zero_guarded(self):
        r = analyze(b'A' * 100, block_size=0)
        self.assertIsInstance(r, EntropyResult)
        self.assertEqual(r.block_size, 4096)

    def test_blocks_created(self):
        data = b'A' * 8192
        r = analyze(data, block_size=1024)
        self.assertEqual(len(r.blocks), 8)

    def test_block_size_respected(self):
        r = analyze(b'x' * 4096, block_size=4096)
        self.assertEqual(r.block_size, 4096)
        self.assertEqual(len(r.blocks), 1)

    def test_returns_entropy_result_instance(self):
        r = analyze(b'test data')
        self.assertIsInstance(r, EntropyResult)

    def test_single_byte_value_zero_entropy(self):
        r = analyze(b'\xAA' * 512)
        self.assertAlmostEqual(r.overall, 0.0, places=5)

    def test_all_256_bytes_max_entropy(self):
        data = bytes(range(256)) * 32
        r = analyze(data)
        self.assertGreater(r.overall, 7.9)
        self.assertTrue(r.suspicious)


class TestEntropyFunction(unittest.TestCase):

    def test_empty_returns_zero(self):
        self.assertEqual(_entropy(b''), 0.0)

    def test_uniform_bytes_zero(self):
        self.assertAlmostEqual(_entropy(b'\x00' * 100), 0.0, places=5)

    def test_two_values_max_one_bit(self):
        data = bytes([0, 1] * 50)
        e = _entropy(data)
        self.assertAlmostEqual(e, 1.0, places=5)

    def test_all_256_values_max_8_bits(self):
        data = bytes(range(256))
        e = _entropy(data)
        self.assertAlmostEqual(e, 8.0, places=5)


class TestClassify(unittest.TestCase):

    def test_high_entropy_label(self):
        self.assertIn('Encrypted', _classify(7.6))

    def test_packed_label(self):
        label = _classify(6.8)
        self.assertIn('Packed', label)

    def test_mixed_label(self):
        label = _classify(5.8)
        self.assertIn('Mixed', label)

    def test_normal_binary_label(self):
        label = _classify(4.0)
        self.assertIn('Normal', label)

    def test_sparse_label(self):
        label = _classify(2.0)
        self.assertIn('Sparse', label)

    def test_uniform_label(self):
        label = _classify(0.0)
        self.assertIn('Uniform', label)


class TestRenderHtml(unittest.TestCase):

    def test_returns_string(self):
        r = analyze(b'hello world ' * 50)
        html = render_html(r)
        self.assertIsInstance(html, str)

    def test_contains_entropy_value(self):
        r = analyze(b'A' * 100)
        html = render_html(r)
        self.assertIn('0.000 bits/byte', html)

    def test_suspicious_badge_present(self):
        import os
        data = os.urandom(8192)
        r = analyze(data)
        html = render_html(r)
        if r.suspicious:
            self.assertIn('SUSPICIOUS', html)

    def test_no_suspicious_badge_when_clean(self):
        r = analyze(b'A' * 1000)
        html = render_html(r)
        self.assertNotIn('SUSPICIOUS', html)

    def test_block_heatmap_included_when_blocks_present(self):
        r = analyze(b'hello world ' * 1000, block_size=512)
        html = render_html(r)
        self.assertIn('Block Entropy Heatmap', html)

    def test_no_heatmap_on_empty(self):
        r = EntropyResult(0.0, 'Empty', [], 4096, False)
        html = render_html(r)
        self.assertNotIn('Heatmap', html)

    def test_label_in_output(self):
        r = analyze(b'A' * 500)
        html = render_html(r)
        self.assertIn(r.label, html)


class TestBarColor(unittest.TestCase):

    def test_high_entropy_red(self):
        self.assertEqual(_bar_color(7.5), '#ef5350')

    def test_medium_high_orange(self):
        self.assertEqual(_bar_color(6.5), '#ffa726')

    def test_medium_yellow(self):
        self.assertEqual(_bar_color(5.0), '#ffca28')

    def test_low_green(self):
        self.assertEqual(_bar_color(2.0), '#4ecca3')


class TestBlockColor(unittest.TestCase):

    def test_returns_rgb_string(self):
        c = _block_color(4.0)
        self.assertTrue(c.startswith('rgb('))

    def test_zero_entropy_green_ish(self):
        c = _block_color(0.0)
        self.assertIn('rgb(', c)

    def test_max_entropy_red_ish(self):
        c = _block_color(8.0)
        self.assertIn('rgb(', c)


if __name__ == '__main__':
    unittest.main()
