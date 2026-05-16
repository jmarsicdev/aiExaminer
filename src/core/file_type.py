"""Magic-byte file type detection for forensic analysis."""

import re

# (offset, magic_bytes, label, category, mime)
_SIGNATURES = [
    # Images
    (0, b'\xff\xd8\xff',                     'JPEG Image',              'image',      'image/jpeg'),
    (0, b'\x89PNG\r\n\x1a\n',               'PNG Image',               'image',      'image/png'),
    (0, b'GIF89a',                           'GIF Image',               'image',      'image/gif'),
    (0, b'GIF87a',                           'GIF Image',               'image',      'image/gif'),
    (0, b'BM',                               'BMP Image',               'image',      'image/bmp'),
    (0, b'II\x2a\x00',                       'TIFF Image (LE)',          'image',      'image/tiff'),
    (0, b'MM\x00\x2a',                       'TIFF Image (BE)',          'image',      'image/tiff'),
    (8, b'WEBP',                             'WebP Image',              'image',      'image/webp'),
    # Documents
    (0, b'%PDF',                             'PDF Document',            'document',   'application/pdf'),
    (0, b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1','MS Office (OLE2)',        'document',   'application/msoffice'),
    (0, b'PK\x03\x04',                      'ZIP / Office Open XML',   'archive',    'application/zip'),
    (0, b'PK\x05\x06',                      'ZIP (empty)',              'archive',    'application/zip'),
    (0, b'PK\x07\x08',                      'ZIP (spanned)',            'archive',    'application/zip'),
    # Archives
    (0, b'Rar!\x1a\x07\x00',               'RAR Archive v4',          'archive',    'application/x-rar'),
    (0, b'Rar!\x1a\x07\x01',               'RAR Archive v5',          'archive',    'application/x-rar'),
    (0, b'7z\xbc\xaf\x27\x1c',             '7-Zip Archive',           'archive',    'application/x-7z-compressed'),
    (0, b'\x1f\x8b',                        'GZip Archive',            'archive',    'application/gzip'),
    (0, b'BZh',                             'BZip2 Archive',           'archive',    'application/x-bzip2'),
    (0, b'\xfd7zXZ\x00',                    'XZ Archive',              'archive',    'application/x-xz'),
    (0, b'ustar',                           'TAR Archive',             'archive',    'application/x-tar'),
    # Executables / Code
    (0, b'MZ',                              'Windows PE (EXE/DLL)',    'executable', 'application/x-msdownload'),
    (0, b'\x7fELF',                         'ELF Executable',          'executable', 'application/x-elf'),
    (0, b'\xfe\xed\xfa\xce',               'Mach-O 32-bit',           'executable', 'application/x-mach-binary'),
    (0, b'\xfe\xed\xfa\xcf',               'Mach-O 64-bit',           'executable', 'application/x-mach-binary'),
    (0, b'\xca\xfe\xba\xbe',               'Java Class / Mach-O Fat', 'executable', 'application/x-java-class'),
    # Databases / Forensic artifacts
    (0, b'SQLite format 3\x00',             'SQLite Database',         'database',   'application/x-sqlite3'),
    (0, b'regf',                            'Windows Registry Hive',   'registry',   'application/x-registry'),
    (0, b'ElfFile\x00',                     'Windows Event Log (EVTX)','log',        'application/x-evtx'),
    (4, b'SCCA',                            'Windows Prefetch',        'forensic',   'application/x-prefetch'),
    (0, b'\x4c\x00\x00\x00\x01\x14\x02\x00','Windows Shortcut (LNK)', 'forensic',   'application/x-ms-shortcut'),
    (0, b'CrOD',                            'Chrome SQLite Journal',   'forensic',   'application/x-chrome-artifact'),
    (0, b'MDMP',                            'Windows Minidump',        'forensic',   'application/x-minidump'),
    (0, b'PAGEDU64',                        'Windows Hibernation',     'forensic',   'application/x-hiberfil'),
    # Network / Capture
    (0, b'\xd4\xc3\xb2\xa1',              'PCAP Capture (LE)',        'network',    'application/x-pcap'),
    (0, b'\xa1\xb2\xc3\xd4',              'PCAP Capture (BE)',        'network',    'application/x-pcap'),
    (0, b'\x0a\x0d\x0d\x0a',              'PCAP-NG Capture',          'network',    'application/x-pcapng'),
    # Audio / Video
    (0, b'ID3',                             'MP3 Audio',               'audio',      'audio/mpeg'),
    (0, b'\xff\xfb',                        'MP3 Audio (no ID3)',       'audio',      'audio/mpeg'),
    (0, b'fLaC',                            'FLAC Audio',              'audio',      'audio/flac'),
    (0, b'OggS',                            'OGG Audio/Video',         'audio',      'application/ogg'),
    (0, b'RIFF',                            'WAV/AVI (RIFF)',           'audio',      'audio/wav'),
    (4, b'ftyp',                            'MP4/MOV Video',           'video',      'video/mp4'),
    (0, b'\x1a\x45\xdf\xa3',              'MKV/WebM Video',           'video',      'video/x-matroska'),
    # Certificates / Keys
    (0, b'-----BEGIN ',                     'PEM Certificate/Key',     'crypto',     'application/x-pem-file'),
    # XML / HTML (text-based, checked after binary signatures)
    (0, b'<?xml',                           'XML Document',            'document',   'application/xml'),
    (0, b'\xef\xbb\xbf<?xml',              'XML Document (UTF-8 BOM)','document',   'application/xml'),
]


def detect_file_type(data: bytes, filename: str = '') -> dict:
    """
    Detect file type from magic bytes + filename fallback.

    Returns:
        {'label': str, 'category': str, 'mime': str}
    """
    header = data[:16] if len(data) >= 16 else data

    for offset, magic, label, category, mime in _SIGNATURES:
        end = offset + len(magic)
        if len(data) >= end and data[offset:end] == magic:
            # Refine ZIP-based Office formats by filename
            if mime == 'application/zip' and filename:
                ext = filename.lower().rsplit('.', 1)[-1]
                _office_map = {
                    'docx': ('Word Document (DOCX)', 'document', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'),
                    'xlsx': ('Excel Workbook (XLSX)', 'document', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'),
                    'pptx': ('PowerPoint (PPTX)', 'document', 'application/vnd.openxmlformats-officedocument.presentationml.presentation'),
                    'apk':  ('Android Package (APK)', 'executable', 'application/vnd.android.package-archive'),
                    'jar':  ('Java Archive (JAR)', 'executable', 'application/java-archive'),
                }
                if ext in _office_map:
                    return dict(zip(('label', 'category', 'mime'), _office_map[ext]))
            # Refine RIFF containers
            if label == 'WAV/AVI (RIFF)' and len(data) >= 12:
                riff_type = data[8:12]
                if riff_type == b'AVI ':
                    return {'label': 'AVI Video', 'category': 'video', 'mime': 'video/avi'}
                if riff_type == b'WAVE':
                    return {'label': 'WAV Audio', 'category': 'audio', 'mime': 'audio/wav'}
            return {'label': label, 'category': category, 'mime': mime}

    # HTML heuristic (case-insensitive text prefix)
    if len(data) >= 9:
        prefix = data[:512].lower()
        if b'<!doctype html' in prefix or b'<html' in prefix:
            return {'label': 'HTML Document', 'category': 'document', 'mime': 'text/html'}

    # Script shebang
    if data[:2] == b'#!':
        return {'label': 'Script File', 'category': 'script', 'mime': 'text/x-shellscript'}

    # Text fallback
    if is_text(data):
        return {'label': 'Plain Text', 'category': 'text', 'mime': 'text/plain'}

    # Extension-based last resort
    if filename:
        _ext_map = {
            'log': ('Log File', 'log', 'text/plain'),
            'csv': ('CSV Data', 'document', 'text/csv'),
            'json': ('JSON Data', 'document', 'application/json'),
            'xml': ('XML Document', 'document', 'application/xml'),
            'py': ('Python Script', 'script', 'text/x-python'),
            'js': ('JavaScript', 'script', 'text/javascript'),
            'bat': ('Batch Script', 'script', 'application/x-bat'),
            'ps1': ('PowerShell Script', 'script', 'application/x-powershell'),
            'vbs': ('VBScript', 'script', 'text/vbscript'),
        }
        ext = filename.lower().rsplit('.', 1)[-1]
        if ext in _ext_map:
            return dict(zip(('label', 'category', 'mime'), _ext_map[ext]))

    return {'label': 'Unknown Binary', 'category': 'unknown', 'mime': 'application/octet-stream'}


def is_text(data: bytes, sample: int = 512) -> bool:
    """True if ≥85% of sampled bytes are printable ASCII or common control chars."""
    if not data:
        return False
    chunk = data[:sample]
    printable = sum(1 for b in chunk if b >= 0x20 or b in (0x09, 0x0a, 0x0d))
    return printable / len(chunk) >= 0.85


def detect_encoding(data: bytes) -> str:
    """Return 'utf-16-le', 'utf-16-be', 'utf-8', or 'latin-1'."""
    if data[:2] == b'\xff\xfe':
        return 'utf-16-le'
    if data[:2] == b'\xfe\xff':
        return 'utf-16-be'
    try:
        data[:4096].decode('utf-8')
        return 'utf-8'
    except UnicodeDecodeError:
        return 'latin-1'
