"""File metadata extraction — EXIF, GPS, timestamps."""

import io
import datetime
from src.core.file_type import detect_file_type

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False


def extract_metadata(file_path: str, content: bytes, entry: dict) -> dict:
    """
    Build a flat metadata dict for a file.

    entry is the dict yielded by any parser's list_directory().
    Expected optional keys: crtime, mtime, atime, ctime, is_deleted.
    """
    ft = detect_file_type(content[:2048], file_path.rsplit('/', 1)[-1])

    meta = {
        'Path':      file_path,
        'File Type': ft['label'],
        'Category':  ft['category'],
        'MIME':      ft['mime'],
        'Size':      f"{entry.get('size', len(content)):,} bytes",
    }

    # Timestamps from parser entry (if available)
    for key, label in [('crtime', 'Created'), ('mtime', 'Modified'),
                        ('atime', 'Accessed'), ('ctime', 'Changed (MFT)')]:
        ts = entry.get(key)
        meta[label] = _ts(ts)

    meta['Deleted'] = 'Yes' if entry.get('is_deleted') else 'No'

    # EXIF for images
    if ft['category'] == 'image' and _PIL_AVAILABLE:
        _add_exif(meta, content)

    return meta


def extract_gps(content: bytes) -> dict | None:
    """Return {'lat': float, 'lon': float, 'maps_url': str} or None."""
    if not _PIL_AVAILABLE:
        return None
    try:
        img = Image.open(io.BytesIO(content))
        exif_raw = img._getexif()
        if not exif_raw:
            return None
        for tag_id, val in exif_raw.items():
            if TAGS.get(tag_id) == 'GPSInfo':
                return _parse_gps_info(val)
    except Exception:
        pass
    return None


# ------------------------------------------------------------------ #
#  Private helpers                                                      #
# ------------------------------------------------------------------ #

def _add_exif(meta: dict, content: bytes) -> None:
    try:
        img = Image.open(io.BytesIO(content))
        meta['Image Size'] = f"{img.width} × {img.height} px"
        meta['Color Mode'] = img.mode

        exif_raw = img._getexif()
        if not exif_raw:
            return

        gps_info = None
        for tag_id, val in exif_raw.items():
            tag = TAGS.get(tag_id, str(tag_id))
            if tag == 'GPSInfo':
                gps_info = val
                continue
            if tag in ('MakerNote', 'UserComment', 'PrintImageMatching'):
                continue
            display_val = str(val)
            if len(display_val) > 120:
                display_val = display_val[:117] + '...'
            meta[f'EXIF: {tag}'] = display_val

        if gps_info:
            gps = _parse_gps_info(gps_info)
            if gps:
                meta['GPS Latitude']  = f"{gps['lat']:.6f}"
                meta['GPS Longitude'] = f"{gps['lon']:.6f}"
                meta['GPS Maps Link'] = gps['maps_url']

    except Exception as e:
        meta['EXIF Error'] = str(e)


def _parse_gps_info(gps_info: dict) -> dict | None:
    try:
        named = {GPSTAGS.get(k, k): v for k, v in gps_info.items()}
        lat = _dms_to_deg(named.get('GPSLatitude'))
        lon = _dms_to_deg(named.get('GPSLongitude'))
        if lat is None or lon is None:
            return None
        if named.get('GPSLatitudeRef', 'N') == 'S':
            lat = -lat
        if named.get('GPSLongitudeRef', 'E') == 'W':
            lon = -lon
        url = f"https://www.google.com/maps?q={lat:.6f},{lon:.6f}"
        return {'lat': lat, 'lon': lon, 'maps_url': url}
    except Exception:
        return None


def _dms_to_deg(dms) -> float | None:
    if not dms or len(dms) < 3:
        return None
    try:
        return float(dms[0]) + float(dms[1]) / 60 + float(dms[2]) / 3600
    except Exception:
        return None


def _ts(value) -> str:
    if value is None:
        return '—'
    if isinstance(value, (int, float)):
        try:
            return datetime.datetime.utcfromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S UTC')
        except Exception:
            return str(value)
    return str(value)
