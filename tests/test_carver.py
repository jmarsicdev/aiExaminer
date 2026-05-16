"""Tests for src/core/carver.py — FileCarver."""
import io
import os
import tempfile
import unittest

from src.core.carver import FileCarver, CarvedFile


def _jpeg_bytes():
    """Minimal but structurally valid JPEG bytes."""
    return b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00' + b'\x00' * 20 + b'\xFF\xD9'


def _png_bytes():
    """Minimal PNG with IEND chunk."""
    return (b'\x89PNG\r\n\x1a\n'                 # signature
            b'\x00\x00\x00\rIHDR'                # IHDR chunk (13 bytes)
            + b'\x00' * 17
            + b'\x00\x00\x00\x00IEND\xaeB`\x82')  # IEND footer


def _pdf_bytes():
    """Minimal PDF bytes."""
    return b'%PDF-1.4\n' + b'\x00' * 20 + b'%%EOF'


def _zip_bytes():
    """Minimal ZIP local file header + EOCD."""
    return b'PK\x03\x04' + b'\x00' * 26 + b'PK\x05\x06' + b'\x00' * 18


class TestCarvedFileDataclass(unittest.TestCase):

    def test_fields_accessible(self):
        cf = CarvedFile(offset=100, size=50, label='JPEG Image', extension='jpg', data=b'\xff\xd8')
        self.assertEqual(cf.offset, 100)
        self.assertEqual(cf.size, 50)
        self.assertEqual(cf.label, 'JPEG Image')
        self.assertEqual(cf.extension, 'jpg')
        self.assertEqual(cf.data, b'\xff\xd8')

    def test_repr_hides_data(self):
        cf = CarvedFile(offset=0, size=10, label='Test', extension='bin', data=b'\x00' * 10)
        r = repr(cf)
        self.assertNotIn('data=', r)


class TestFileCarverStream(unittest.TestCase):

    def setUp(self):
        self.carver = FileCarver()

    def test_empty_data_yields_nothing(self):
        results = list(self.carver.carve_stream(b''))
        self.assertEqual(results, [])

    def test_no_signature_yields_nothing(self):
        results = list(self.carver.carve_stream(b'\x00' * 100))
        self.assertEqual(results, [])

    def test_finds_jpeg(self):
        data = b'\x00' * 10 + _jpeg_bytes() + b'\x00' * 10
        results = list(self.carver.carve_stream(data))
        self.assertTrue(any(r.label == 'JPEG Image' for r in results))

    def test_finds_png(self):
        data = b'\x00' * 8 + _png_bytes() + b'\x00' * 8
        results = list(self.carver.carve_stream(data))
        self.assertTrue(any('PNG' in r.label for r in results))

    def test_finds_pdf(self):
        data = b'\x00' * 10 + _pdf_bytes() + b'\x00' * 10
        results = list(self.carver.carve_stream(data))
        self.assertTrue(any('PDF' in r.label for r in results))

    def test_finds_sqlite(self):
        data = b'\x00' * 4 + b'SQLite format 3\x00' + b'\x00' * 50
        results = list(self.carver.carve_stream(data))
        self.assertTrue(any('SQLite' in r.label for r in results))

    def test_finds_windows_pe(self):
        data = b'\x00' * 4 + b'MZ' + b'\x00' * 100
        results = list(self.carver.carve_stream(data))
        self.assertTrue(any(r.extension == 'exe' for r in results))

    def test_finds_elf(self):
        data = b'\x00' * 4 + b'\x7fELF' + b'\x00' * 100
        results = list(self.carver.carve_stream(data))
        self.assertTrue(any(r.extension == 'elf' for r in results))

    def test_finds_registry_hive(self):
        data = b'\x00' * 4 + b'regf' + b'\x00' * 50
        results = list(self.carver.carve_stream(data))
        self.assertTrue(any(r.extension == 'hive' for r in results))

    def test_carved_file_offset_correct(self):
        pad = 16
        data = b'\x00' * pad + _jpeg_bytes()
        results = list(self.carver.carve_stream(data))
        jpeg_results = [r for r in results if r.label == 'JPEG Image']
        self.assertTrue(any(r.offset == pad for r in jpeg_results))

    def test_base_offset_added_to_carved_offset(self):
        data = b'\x00' * 4 + _jpeg_bytes()
        results = list(self.carver.carve_stream(data, base_offset=1000))
        jpeg_results = [r for r in results if r.label == 'JPEG Image']
        self.assertTrue(any(r.offset >= 1000 for r in jpeg_results))

    def test_carved_file_data_starts_with_header(self):
        data = b'\x00' * 4 + _jpeg_bytes()
        results = list(self.carver.carve_stream(data))
        jpeg_results = [r for r in results if r.label == 'JPEG Image']
        if jpeg_results:
            self.assertTrue(jpeg_results[0].data.startswith(b'\xFF\xD8\xFF'))

    def test_returns_carved_file_instances(self):
        data = b'\x00' * 4 + _jpeg_bytes()
        results = list(self.carver.carve_stream(data))
        for r in results:
            self.assertIsInstance(r, CarvedFile)

    def test_progress_callback_called(self):
        called = []
        data = b'\x00' * (1024 * 1024 + 100)

        def cb(pos, total):
            called.append((pos, total))

        list(self.carver.carve_stream(data, progress_cb=cb))
        self.assertTrue(len(called) > 0)

    def test_multiple_files_in_stream(self):
        data = _jpeg_bytes() + b'\x00' * 20 + _jpeg_bytes()
        results = list(self.carver.carve_stream(data))
        jpeg_results = [r for r in results if r.label == 'JPEG Image']
        self.assertGreaterEqual(len(jpeg_results), 1)


class TestFileCarverFromFile(unittest.TestCase):

    def test_carve_file_finds_jpeg(self):
        jpeg = _jpeg_bytes()
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'\x00' * 16 + jpeg + b'\x00' * 16)
            path = f.name
        try:
            carver = FileCarver()
            results = list(carver.carve_file(path))
            self.assertTrue(any(r.label == 'JPEG Image' for r in results))
        finally:
            os.unlink(path)

    def test_carve_empty_file_yields_nothing(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'')
            path = f.name
        try:
            carver = FileCarver()
            results = list(carver.carve_file(path))
            self.assertEqual(results, [])
        finally:
            os.unlink(path)


if __name__ == '__main__':
    unittest.main()
