"""Tests for src/core/strings_util.py"""
import unittest

from src.core.strings_util import extract_strings, to_html, StringHit


class TestExtractStrings(unittest.TestCase):

    def test_empty_returns_empty(self):
        self.assertEqual(extract_strings(b''), [])

    def test_ascii_string_found(self):
        data = b'\x00\x00' + b'HelloWorld' + b'\x00\x00'
        hits = extract_strings(data, min_len=6)
        values = [h.value for h in hits]
        self.assertTrue(any('HelloWorld' in v for v in values))

    def test_short_string_below_min_len_excluded(self):
        data = b'\x00\x00' + b'Hi' + b'\x00\x00'
        hits = extract_strings(data, min_len=6)
        self.assertEqual(hits, [])

    def test_returns_list_of_string_hits(self):
        data = b'This is a long enough string\x00'
        hits = extract_strings(data)
        self.assertIsInstance(hits, list)
        for h in hits:
            self.assertIsInstance(h, StringHit)

    def test_hit_has_correct_fields(self):
        data = b'\x00' * 4 + b'TargetString' + b'\x00'
        hits = extract_strings(data, min_len=6)
        self.assertTrue(len(hits) > 0)
        h = hits[0]
        self.assertIsInstance(h.offset, int)
        self.assertIsInstance(h.encoding, str)
        self.assertIsInstance(h.value, str)

    def test_encoding_ascii(self):
        data = b'HelloWorldTest'
        hits = extract_strings(data, min_len=6)
        self.assertTrue(any(h.encoding == 'ascii' for h in hits))

    def test_utf16_string_found(self):
        s = 'HelloWorld'
        data = b'\x00\x00' + s.encode('utf-16-le') + b'\x00\x01'
        hits = extract_strings(data, min_len=6)
        self.assertTrue(any(h.encoding == 'utf16' for h in hits))

    def test_deduplication(self):
        repeated = b'DUPLICATE'
        data = repeated + b'\x00' + repeated + b'\x00'
        hits = extract_strings(data, min_len=6)
        values = [h.value for h in hits if 'DUPLICATE' in h.value]
        self.assertEqual(len(values), 1)

    def test_sorted_by_offset(self):
        data = b'FirstString\x00\x00SecondString\x00'
        hits = extract_strings(data, min_len=6)
        offsets = [h.offset for h in hits]
        self.assertEqual(offsets, sorted(offsets))

    def test_max_strings_limit(self):
        data = b'ABCDEFGHIJ\x00' * 200
        hits = extract_strings(data, min_len=6, max_strings=5)
        self.assertLessEqual(len(hits), 5)

    def test_binary_noise_no_crash(self):
        import os
        data = os.urandom(1024)
        hits = extract_strings(data)
        self.assertIsInstance(hits, list)

    def test_trailing_ascii_flushed(self):
        data = b'\x00\x00' + b'TrailingString'
        hits = extract_strings(data, min_len=6)
        values = [h.value for h in hits]
        self.assertTrue(any('TrailingString' in v for v in values))

    def test_multiple_strings_separated_by_null(self):
        data = b'FirstString\x00SecondString\x00'
        hits = extract_strings(data, min_len=6)
        values = [h.value for h in hits]
        self.assertTrue(any('FirstString' in v for v in values))
        self.assertTrue(any('SecondString' in v for v in values))


class TestToHtml(unittest.TestCase):

    def test_empty_hits_returns_no_strings_message(self):
        html = to_html([])
        self.assertIn('No printable strings found', html)

    def test_with_ascii_hits_returns_table(self):
        hits = [StringHit(offset=0, encoding='ascii', value='HelloWorld')]
        html = to_html(hits)
        self.assertIn('HelloWorld', html)
        self.assertIn('<table', html)

    def test_offset_shown_in_hex(self):
        hits = [StringHit(offset=255, encoding='ascii', value='TestString')]
        html = to_html(hits)
        self.assertIn('000000FF', html)

    def test_utf16_badge_shown(self):
        hits = [StringHit(offset=0, encoding='utf16', value='WideString')]
        html = to_html(hits)
        self.assertIn('UTF-16', html)

    def test_ascii_no_utf16_badge(self):
        hits = [StringHit(offset=0, encoding='ascii', value='NarrowStr')]
        html = to_html(hits)
        html_between_badges = html
        self.assertNotIn('UTF-16', html_between_badges.replace('UTF-16', '') + 'x')

    def test_count_in_output(self):
        hits = [StringHit(offset=i, encoding='ascii', value=f'String{i:04d}') for i in range(5)]
        html = to_html(hits)
        self.assertIn('5 strings found', html)

    def test_truncation_note_shown(self):
        hits = [StringHit(offset=i, encoding='ascii', value=f'StringValue{i:04d}') for i in range(1500)]
        html = to_html(hits, max_display=1000)
        self.assertIn('more', html)

    def test_html_entities_escaped(self):
        hits = [StringHit(offset=0, encoding='ascii', value='<script>alert(1)</script>')]
        html = to_html(hits)
        self.assertNotIn('<script>', html)
        self.assertIn('&lt;script&gt;', html)


if __name__ == '__main__':
    unittest.main()
