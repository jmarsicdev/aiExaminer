"""Tests for src/core/metadata.py"""
import io
import unittest

from src.core.metadata import extract_metadata, extract_gps, _ts, _dms_to_deg, _parse_gps_info

try:
    from PIL import Image
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False


def _make_jpeg(width=32, height=32, color=(100, 150, 200)):
    img = Image.new('RGB', (width, height), color=color)
    buf = io.BytesIO()
    img.save(buf, format='JPEG', quality=85)
    return buf.getvalue()


class TestExtractMetadata(unittest.TestCase):

    def _entry(self, **kwargs):
        base = {'name': 'test.txt', 'size': 100, 'type': 'File',
                'crtime': None, 'mtime': None, 'atime': None, 'ctime': None,
                'is_deleted': False}
        base.update(kwargs)
        return base

    def test_returns_dict(self):
        result = extract_metadata('/test.txt', b'Hello world', self._entry())
        self.assertIsInstance(result, dict)

    def test_path_in_result(self):
        result = extract_metadata('/foo/bar.txt', b'Hello world', self._entry())
        self.assertEqual(result['Path'], '/foo/bar.txt')

    def test_file_type_label_present(self):
        result = extract_metadata('/test.txt', b'Hello world', self._entry())
        self.assertIn('File Type', result)

    def test_category_present(self):
        result = extract_metadata('/test.txt', b'Hello world', self._entry())
        self.assertIn('Category', result)

    def test_size_formatted(self):
        result = extract_metadata('/test.txt', b'Hello world', self._entry(size=1000))
        self.assertIn('Size', result)
        self.assertIn('1,000', result['Size'])

    def test_deleted_yes(self):
        result = extract_metadata('/test.txt', b'Hello world', self._entry(is_deleted=True))
        self.assertEqual(result['Deleted'], 'Yes')

    def test_deleted_no(self):
        result = extract_metadata('/test.txt', b'Hello world', self._entry(is_deleted=False))
        self.assertEqual(result['Deleted'], 'No')

    def test_timestamps_dash_when_none(self):
        result = extract_metadata('/test.txt', b'data', self._entry())
        self.assertEqual(result['Created'], '—')
        self.assertEqual(result['Modified'], '—')

    def test_mtime_unix_timestamp_converted(self):
        result = extract_metadata('/test.txt', b'data', self._entry(mtime=0))
        self.assertIn('1970', result['Modified'])

    def test_jpeg_category_detected(self):
        jpeg_data = b'\xff\xd8\xff' + b'\x00' * 100
        result = extract_metadata('/photo.jpg', jpeg_data, self._entry(name='photo.jpg'))
        self.assertEqual(result['Category'], 'image')

    def test_image_exif_error_key_present_on_non_image(self):
        jpeg_data = b'\xff\xd8\xff' + b'\x00' * 20
        result = extract_metadata('/photo.jpg', jpeg_data, self._entry(name='photo.jpg'))
        # PIL may raise on truncated JPEG — should not crash
        self.assertIsInstance(result, dict)

    def test_pdf_category(self):
        pdf_data = b'%PDF-1.4\n' + b'\x00' * 100
        result = extract_metadata('/doc.pdf', pdf_data, self._entry(name='doc.pdf'))
        self.assertEqual(result['Category'], 'document')


class TestTs(unittest.TestCase):

    def test_none_returns_dash(self):
        self.assertEqual(_ts(None), '—')

    def test_int_zero_epoch(self):
        result = _ts(0)
        self.assertIn('1970', result)

    def test_float_timestamp(self):
        result = _ts(1000000.0)
        self.assertIsInstance(result, str)
        self.assertIn('UTC', result)

    def test_string_passthrough(self):
        self.assertEqual(_ts('2024-01-01'), '2024-01-01')

    def test_negative_int_returns_str(self):
        result = _ts(-999999999999)
        self.assertIsInstance(result, str)


@unittest.skipUnless(_PIL_AVAILABLE, 'PIL not installed')
class TestExtractMetadataWithJpeg(unittest.TestCase):

    def _entry(self, **kwargs):
        base = {'name': 'photo.jpg', 'size': 100, 'type': 'File',
                'crtime': None, 'mtime': None, 'atime': None, 'ctime': None,
                'is_deleted': False}
        base.update(kwargs)
        return base

    def test_jpeg_category_is_image(self):
        data = _make_jpeg()
        result = extract_metadata('/photo.jpg', data, self._entry())
        self.assertEqual(result['Category'], 'image')

    def test_jpeg_image_size_key_present(self):
        data = _make_jpeg(width=32, height=32)
        result = extract_metadata('/photo.jpg', data, self._entry())
        self.assertIn('Image Size', result)
        self.assertIn('32', result['Image Size'])

    def test_jpeg_color_mode_present(self):
        data = _make_jpeg()
        result = extract_metadata('/photo.jpg', data, self._entry())
        self.assertIn('Color Mode', result)
        self.assertEqual(result['Color Mode'], 'RGB')


@unittest.skipUnless(_PIL_AVAILABLE, 'PIL not installed')
class TestExtractGps(unittest.TestCase):

    def test_returns_none_for_plain_jpeg_no_exif(self):
        data = _make_jpeg()
        result = extract_gps(data)
        self.assertIsNone(result)

    def test_returns_none_for_empty_bytes(self):
        result = extract_gps(b'')
        self.assertIsNone(result)

    def test_returns_none_for_corrupt_data(self):
        result = extract_gps(b'\xff\xd8\xff' + b'\x00' * 5)
        self.assertIsNone(result)


class TestParseGpsInfo(unittest.TestCase):

    def test_valid_gps_north_east(self):
        gps_info = {
            1: 'N', 2: (40.0, 26.0, 46.56),
            3: 'E', 4: (79.0, 58.0, 55.56),
        }
        result = _parse_gps_info(gps_info)
        self.assertIsNotNone(result)
        self.assertIn('lat', result)
        self.assertIn('lon', result)
        self.assertIn('maps_url', result)
        self.assertGreater(result['lat'], 0)
        self.assertGreater(result['lon'], 0)
        self.assertIn('https://www.google.com/maps', result['maps_url'])

    def test_valid_gps_south_west(self):
        gps_info = {
            1: 'S', 2: (33.0, 51.0, 54.0),
            3: 'W', 4: (70.0, 40.0, 11.0),
        }
        result = _parse_gps_info(gps_info)
        self.assertIsNotNone(result)
        self.assertLess(result['lat'], 0)
        self.assertLess(result['lon'], 0)

    def test_missing_latitude_returns_none(self):
        gps_info = {3: 'E', 4: (10.0, 0.0, 0.0)}
        result = _parse_gps_info(gps_info)
        self.assertIsNone(result)

    def test_missing_longitude_returns_none(self):
        gps_info = {1: 'N', 2: (10.0, 0.0, 0.0)}
        result = _parse_gps_info(gps_info)
        self.assertIsNone(result)

    def test_empty_dict_returns_none(self):
        result = _parse_gps_info({})
        self.assertIsNone(result)

    def test_maps_url_format(self):
        gps_info = {
            1: 'N', 2: (51.0, 30.0, 0.0),
            3: 'W', 4: (0.0, 7.0, 0.0),
        }
        result = _parse_gps_info(gps_info)
        self.assertIsNotNone(result)
        self.assertIn('q=', result['maps_url'])


class TestDmsToDeg(unittest.TestCase):

    def test_none_returns_none(self):
        self.assertIsNone(_dms_to_deg(None))

    def test_empty_tuple_returns_none(self):
        self.assertIsNone(_dms_to_deg(()))

    def test_short_tuple_returns_none(self):
        self.assertIsNone(_dms_to_deg((10, 20)))

    def test_valid_conversion(self):
        result = _dms_to_deg((40, 26, 46.56))
        self.assertAlmostEqual(result, 40.4462667, places=4)

    def test_zero_zero_zero(self):
        result = _dms_to_deg((0, 0, 0))
        self.assertAlmostEqual(result, 0.0)

    def test_fractions_object(self):
        from fractions import Fraction
        result = _dms_to_deg((Fraction(40, 1), Fraction(26, 1), Fraction(4656, 100)))
        self.assertIsNotNone(result)
        self.assertAlmostEqual(result, 40.4462667, places=4)

    def test_non_numeric_triggers_exception_path(self):
        # float('x') raises ValueError → hits except branch in _dms_to_deg
        result = _dms_to_deg(('x', 'y', 'z'))
        self.assertIsNone(result)


class TestParseGpsInfoExceptionPath(unittest.TestCase):

    def test_non_dict_triggers_exception_returns_none(self):
        # Passing a non-dict causes .items() to fail → hits except branch
        result = _parse_gps_info("not a dict")
        self.assertIsNone(result)

    def test_dict_with_bad_values_returns_none(self):
        # Keys that produce None lat/lon
        result = _parse_gps_info({})
        self.assertIsNone(result)


@unittest.skipUnless(_PIL_AVAILABLE, 'PIL not installed')
class TestExtractMetadataExifMocked(unittest.TestCase):
    """Mock PIL._getexif to cover the EXIF processing loop in _add_exif."""

    def _entry(self, **kwargs):
        base = {'name': 'photo.jpg', 'size': 100, 'type': 'File',
                'crtime': None, 'mtime': None, 'atime': None, 'ctime': None,
                'is_deleted': False}
        base.update(kwargs)
        return base

    def test_add_exif_with_mock_tags(self):
        from unittest.mock import patch, MagicMock
        from PIL.ExifTags import TAGS

        # Find a tag ID for a simple string tag (e.g. Make = 271)
        make_tag_id = next(k for k, v in TAGS.items() if v == 'Make')

        mock_img = MagicMock()
        mock_img.width = 100
        mock_img.height = 100
        mock_img.mode = 'RGB'
        mock_img._getexif.return_value = {make_tag_id: 'TestCamera'}

        jpeg_data = _make_jpeg()
        with patch('src.core.metadata.Image.open', return_value=mock_img):
            result = extract_metadata('/photo.jpg', jpeg_data, self._entry())

        self.assertIn('EXIF: Make', result)
        self.assertEqual(result['EXIF: Make'], 'TestCamera')

    def test_extract_gps_with_mock_exif(self):
        from unittest.mock import patch, MagicMock
        from PIL.ExifTags import TAGS

        gps_tag_id = next(k for k, v in TAGS.items() if v == 'GPSInfo')
        mock_gps = {1: 'N', 2: (51.0, 30.0, 0.0), 3: 'W', 4: (0.0, 7.0, 0.0)}

        mock_img = MagicMock()
        mock_img._getexif.return_value = {gps_tag_id: mock_gps}

        jpeg_data = _make_jpeg()
        with patch('src.core.metadata.Image.open', return_value=mock_img):
            result = extract_gps(jpeg_data)

        self.assertIsNotNone(result)
        self.assertIn('lat', result)
        self.assertIn('lon', result)
        self.assertIn('maps_url', result)

    def test_extract_gps_loop_no_gps_tag_returns_none(self):
        from unittest.mock import patch, MagicMock
        from PIL.ExifTags import TAGS

        make_tag_id = next(k for k, v in TAGS.items() if v == 'Make')

        mock_img = MagicMock()
        mock_img._getexif.return_value = {make_tag_id: 'TestCamera'}

        jpeg_data = _make_jpeg()
        with patch('src.core.metadata.Image.open', return_value=mock_img):
            result = extract_gps(jpeg_data)

        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
