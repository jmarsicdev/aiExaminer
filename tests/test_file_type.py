"""Tests for src/core/file_type.py — magic-byte detection, is_text, detect_encoding."""
import unittest

from src.core.file_type import detect_file_type, is_text, detect_encoding


class TestDetectFileTypeImages(unittest.TestCase):

    def test_jpeg(self):
        r = detect_file_type(b'\xff\xd8\xff' + b'\x00' * 20)
        self.assertEqual(r['category'], 'image')
        self.assertIn('JPEG', r['label'])

    def test_png(self):
        r = detect_file_type(b'\x89PNG\r\n\x1a\n' + b'\x00' * 10)
        self.assertEqual(r['category'], 'image')
        self.assertIn('PNG', r['label'])

    def test_gif89a(self):
        r = detect_file_type(b'GIF89a' + b'\x00' * 10)
        self.assertEqual(r['category'], 'image')
        self.assertIn('GIF', r['label'])

    def test_gif87a(self):
        r = detect_file_type(b'GIF87a' + b'\x00' * 10)
        self.assertEqual(r['category'], 'image')

    def test_bmp(self):
        r = detect_file_type(b'BM' + b'\x00' * 20)
        self.assertEqual(r['category'], 'image')
        self.assertIn('BMP', r['label'])

    def test_tiff_le(self):
        r = detect_file_type(b'II\x2a\x00' + b'\x00' * 10)
        self.assertEqual(r['category'], 'image')
        self.assertIn('TIFF', r['label'])

    def test_tiff_be(self):
        r = detect_file_type(b'MM\x00\x2a' + b'\x00' * 10)
        self.assertEqual(r['category'], 'image')

    def test_webp(self):
        data = b'RIFF' + b'\x00' * 4 + b'WEBP' + b'\x00' * 10
        r = detect_file_type(data)
        self.assertEqual(r['category'], 'image')
        self.assertIn('WebP', r['label'])


class TestDetectFileTypeDocuments(unittest.TestCase):

    def test_pdf(self):
        r = detect_file_type(b'%PDF-1.4' + b'\x00' * 10)
        self.assertEqual(r['category'], 'document')
        self.assertIn('PDF', r['label'])

    def test_ole2_msoffice(self):
        r = detect_file_type(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' + b'\x00' * 10)
        self.assertEqual(r['category'], 'document')

    def test_zip_no_extension(self):
        r = detect_file_type(b'PK\x03\x04' + b'\x00' * 20)
        self.assertEqual(r['category'], 'archive')

    def test_docx_via_zip_extension(self):
        r = detect_file_type(b'PK\x03\x04' + b'\x00' * 20, 'report.docx')
        self.assertEqual(r['category'], 'document')
        self.assertIn('Word', r['label'])

    def test_xlsx_via_zip_extension(self):
        r = detect_file_type(b'PK\x03\x04' + b'\x00' * 20, 'data.xlsx')
        self.assertEqual(r['category'], 'document')
        self.assertIn('Excel', r['label'])

    def test_pptx_via_zip_extension(self):
        r = detect_file_type(b'PK\x03\x04' + b'\x00' * 20, 'slides.pptx')
        self.assertEqual(r['category'], 'document')

    def test_apk_via_zip_extension(self):
        r = detect_file_type(b'PK\x03\x04' + b'\x00' * 20, 'app.apk')
        self.assertEqual(r['category'], 'executable')

    def test_jar_via_zip_extension(self):
        r = detect_file_type(b'PK\x03\x04' + b'\x00' * 20, 'app.jar')
        self.assertEqual(r['category'], 'executable')

    def test_xml_magic(self):
        r = detect_file_type(b'<?xml version="1.0"?>' + b'\x00' * 5)
        self.assertEqual(r['category'], 'document')

    def test_html_doctype_heuristic(self):
        r = detect_file_type(b'<!DOCTYPE html><html><body>')
        self.assertEqual(r['category'], 'document')
        self.assertIn('HTML', r['label'])

    def test_html_tag_heuristic(self):
        r = detect_file_type(b'<html lang="en"><head>')
        self.assertEqual(r['category'], 'document')


class TestDetectFileTypeArchives(unittest.TestCase):

    def test_rar4(self):
        r = detect_file_type(b'Rar!\x1a\x07\x00' + b'\x00' * 10)
        self.assertEqual(r['category'], 'archive')

    def test_7zip(self):
        r = detect_file_type(b'7z\xbc\xaf\x27\x1c' + b'\x00' * 10)
        self.assertEqual(r['category'], 'archive')
        self.assertIn('7-Zip', r['label'])

    def test_gzip(self):
        r = detect_file_type(b'\x1f\x8b' + b'\x00' * 20)
        self.assertEqual(r['category'], 'archive')

    def test_bzip2(self):
        r = detect_file_type(b'BZh' + b'\x00' * 20)
        self.assertEqual(r['category'], 'archive')

    def test_xz(self):
        r = detect_file_type(b'\xfd7zXZ\x00' + b'\x00' * 10)
        self.assertEqual(r['category'], 'archive')


class TestDetectFileTypeExecutables(unittest.TestCase):

    def test_windows_pe(self):
        r = detect_file_type(b'MZ' + b'\x00' * 20)
        self.assertEqual(r['category'], 'executable')
        self.assertIn('PE', r['label'])

    def test_elf(self):
        r = detect_file_type(b'\x7fELF' + b'\x00' * 20)
        self.assertEqual(r['category'], 'executable')
        self.assertIn('ELF', r['label'])

    def test_macho_32(self):
        r = detect_file_type(b'\xfe\xed\xfa\xce' + b'\x00' * 20)
        self.assertEqual(r['category'], 'executable')

    def test_macho_64(self):
        r = detect_file_type(b'\xfe\xed\xfa\xcf' + b'\x00' * 20)
        self.assertEqual(r['category'], 'executable')


class TestDetectFileTypeForensic(unittest.TestCase):

    def test_sqlite(self):
        r = detect_file_type(b'SQLite format 3\x00' + b'\x00' * 10)
        self.assertEqual(r['category'], 'database')

    def test_registry_hive(self):
        r = detect_file_type(b'regf' + b'\x00' * 20)
        self.assertEqual(r['category'], 'registry')

    def test_evtx_log(self):
        r = detect_file_type(b'ElfFile\x00' + b'\x00' * 10)
        self.assertEqual(r['category'], 'log')

    def test_pcap_le(self):
        r = detect_file_type(b'\xd4\xc3\xb2\xa1' + b'\x00' * 20)
        self.assertEqual(r['category'], 'network')

    def test_pcap_be(self):
        r = detect_file_type(b'\xa1\xb2\xc3\xd4' + b'\x00' * 20)
        self.assertEqual(r['category'], 'network')

    def test_pem_certificate(self):
        r = detect_file_type(b'-----BEGIN CERTIFICATE-----\n')
        self.assertEqual(r['category'], 'crypto')


class TestDetectFileTypeMediaAndRiff(unittest.TestCase):

    def test_mp3_id3(self):
        r = detect_file_type(b'ID3' + b'\x00' * 20)
        self.assertEqual(r['category'], 'audio')

    def test_flac(self):
        r = detect_file_type(b'fLaC' + b'\x00' * 20)
        self.assertEqual(r['category'], 'audio')

    def test_ogg(self):
        r = detect_file_type(b'OggS' + b'\x00' * 20)
        self.assertEqual(r['category'], 'audio')

    def test_mkv(self):
        r = detect_file_type(b'\x1a\x45\xdf\xa3' + b'\x00' * 20)
        self.assertEqual(r['category'], 'video')

    def test_mp4_ftyp(self):
        data = b'\x00' * 4 + b'ftyp' + b'\x00' * 20
        r = detect_file_type(data)
        self.assertEqual(r['category'], 'video')

    def test_riff_wav(self):
        data = b'RIFF' + b'\x00' * 4 + b'WAVE' + b'\x00' * 10
        r = detect_file_type(data)
        self.assertEqual(r['category'], 'audio')
        self.assertIn('WAV', r['label'])

    def test_riff_avi(self):
        data = b'RIFF' + b'\x00' * 4 + b'AVI ' + b'\x00' * 10
        r = detect_file_type(data)
        self.assertEqual(r['category'], 'video')
        self.assertIn('AVI', r['label'])


class TestDetectFileTypeScriptAndFallback(unittest.TestCase):

    def test_shebang_script(self):
        r = detect_file_type(b'#!/usr/bin/python3\n')
        self.assertEqual(r['category'], 'script')

    def test_log_extension_fallback(self):
        r = detect_file_type(b'\x00' * 50, 'system.log')
        self.assertEqual(r['category'], 'log')

    def test_python_extension_fallback(self):
        r = detect_file_type(b'\x00' * 50, 'script.py')
        self.assertEqual(r['category'], 'script')

    def test_bat_extension_fallback(self):
        r = detect_file_type(b'\x00' * 50, 'run.bat')
        self.assertEqual(r['category'], 'script')

    def test_json_extension_fallback(self):
        r = detect_file_type(b'\x00' * 50, 'data.json')
        self.assertEqual(r['category'], 'document')

    def test_csv_extension_fallback(self):
        r = detect_file_type(b'\x00' * 50, 'data.csv')
        self.assertEqual(r['category'], 'document')

    def test_ps1_extension_fallback(self):
        r = detect_file_type(b'\x00' * 50, 'script.ps1')
        self.assertEqual(r['category'], 'script')

    def test_vbs_extension_fallback(self):
        r = detect_file_type(b'\x00' * 50, 'macro.vbs')
        self.assertEqual(r['category'], 'script')

    def test_plain_text_fallback(self):
        r = detect_file_type(b'Just some plain text here without a magic sig.')
        self.assertEqual(r['category'], 'text')

    def test_unknown_binary_fallback(self):
        r = detect_file_type(b'\x00\x01\x02\x03\x04\x05' * 10)
        self.assertEqual(r['category'], 'unknown')

    def test_returns_dict_with_required_keys(self):
        r = detect_file_type(b'\x00' * 20)
        self.assertIn('label', r)
        self.assertIn('category', r)
        self.assertIn('mime', r)


class TestIsText(unittest.TestCase):

    def test_plain_ascii_is_text(self):
        self.assertTrue(is_text(b'Hello, world! This is plain text.'))

    def test_binary_not_text(self):
        # is_text considers bytes >= 0x20 printable (includes extended ASCII);
        # data must be dominated by control bytes (< 0x20) to fail the 85% bar.
        data = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f' * 100
        self.assertFalse(is_text(data))

    def test_empty_not_text(self):
        self.assertFalse(is_text(b''))

    def test_tabs_and_newlines_ok(self):
        self.assertTrue(is_text(b'line1\nline2\ttab\r\n'))

    def test_null_heavy_data_not_text(self):
        # 90% null bytes → 10% printable → below 85% threshold
        data = b'\x00' * 900 + b'A' * 100
        self.assertFalse(is_text(data))


class TestDetectEncoding(unittest.TestCase):

    def test_utf16_le_bom(self):
        self.assertEqual(detect_encoding(b'\xff\xfe' + b'A\x00B\x00'), 'utf-16-le')

    def test_utf16_be_bom(self):
        self.assertEqual(detect_encoding(b'\xfe\xff' + b'\x00A\x00B'), 'utf-16-be')

    def test_utf8(self):
        self.assertEqual(detect_encoding(b'Hello world'), 'utf-8')

    def test_latin1_fallback(self):
        data = bytes([0x80, 0x81, 0x82, 0x83] * 100)
        self.assertEqual(detect_encoding(data), 'latin-1')


if __name__ == '__main__':
    unittest.main()
