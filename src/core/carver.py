"""
File carver — scans a raw byte stream for file-header signatures and extracts
complete files. Yields CarvedFile dataclass instances.

Supports 25+ formats including JPEG, PNG, PDF, ZIP/Office, SQLite, EXE, ELF,
MP4, AVI, MP3, GIF, BMP, 7z, RAR, GZIP, EVTX, and registry hives.
"""

import io
import os
from dataclasses import dataclass, field
from typing import Generator


@dataclass
class CarvedFile:
    offset:    int
    size:      int
    label:     str          # e.g. "JPEG Image"
    extension: str          # e.g. "jpg"
    data:      bytes = field(repr=False)


# ------------------------------------------------------------------ #
#  Signature catalogue                                                  #
# ------------------------------------------------------------------ #

# Each entry: (label, extension, header_bytes, footer_bytes_or_None, max_size)
# footer=None means carve up to max_size bytes

_SIGS: list[tuple[str, str, bytes, bytes | None, int]] = [
    # Images
    ('JPEG Image',          'jpg',   b'\xFF\xD8\xFF',              b'\xFF\xD9',              30 * 1024 * 1024),
    ('PNG Image',           'png',   b'\x89PNG\r\n\x1a\n',        b'IEND\xaeB`\x82',       30 * 1024 * 1024),
    ('GIF Image',           'gif',   b'GIF87a',                   b'\x00\x3B',              10 * 1024 * 1024),
    ('GIF Image',           'gif',   b'GIF89a',                   b'\x00\x3B',              10 * 1024 * 1024),
    ('BMP Image',           'bmp',   b'BM',                       None,                      5 * 1024 * 1024),
    ('TIFF Image',          'tiff',  b'II*\x00',                  None,                     30 * 1024 * 1024),
    ('TIFF Image',          'tiff',  b'MM\x00*',                  None,                     30 * 1024 * 1024),
    ('WebP Image',          'webp',  b'RIFF',                     None,                     20 * 1024 * 1024),

    # Documents
    ('PDF Document',        'pdf',   b'%PDF-',                    b'%%EOF',                100 * 1024 * 1024),
    ('Office Open XML',     'docx',  b'PK\x03\x04',               None,                     50 * 1024 * 1024),
    ('OLE Document',        'doc',   b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', None,           50 * 1024 * 1024),

    # Archives
    ('ZIP Archive',         'zip',   b'PK\x03\x04',               b'PK\x05\x06',          200 * 1024 * 1024),
    ('RAR Archive',         'rar',   b'Rar!\x1a\x07\x00',         None,                    200 * 1024 * 1024),
    ('RAR5 Archive',        'rar',   b'Rar!\x1a\x07\x01\x00',     None,                    200 * 1024 * 1024),
    ('7-Zip Archive',       '7z',    b'7z\xBC\xAF\x27\x1C',      None,                    200 * 1024 * 1024),
    ('GZIP Archive',        'gz',    b'\x1F\x8B\x08',             None,                     50 * 1024 * 1024),

    # Executables
    ('Windows PE/EXE',      'exe',   b'MZ',                       None,                     50 * 1024 * 1024),
    ('ELF Binary',          'elf',   b'\x7FELF',                  None,                     50 * 1024 * 1024),

    # Databases
    ('SQLite Database',     'db',    b'SQLite format 3\x00',      None,                    500 * 1024 * 1024),

    # Media
    ('MP3 Audio',           'mp3',   b'ID3',                      None,                     30 * 1024 * 1024),
    ('MP4/MOV Video',       'mp4',   b'\x00\x00\x00\x18ftyp',    None,                    500 * 1024 * 1024),
    ('MP4/M4V Video',       'mp4',   b'\x00\x00\x00\x1Cftyp',    None,                    500 * 1024 * 1024),
    ('AVI Video',           'avi',   b'RIFF',                     b'RIFF',                 500 * 1024 * 1024),
    ('WAV Audio',           'wav',   b'RIFF',                     None,                     50 * 1024 * 1024),

    # Forensic / Windows artifacts
    ('Windows Registry Hive', 'hive', b'regf',                   None,                    100 * 1024 * 1024),
    ('Windows Event Log',   'evtx',  b'ElfFile\x00',              None,                    100 * 1024 * 1024),
    ('Windows Prefetch',    'pf',    b'SCCA',                     None,                      2 * 1024 * 1024),
    ('Windows Thumbs DB',   'db',    b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', None,          10 * 1024 * 1024),

    # Email
    ('Outlook PST',         'pst',   b'!\xBF\x11\xBE\x14\xC4\x00\x00', None,             2 * 1024 * 1024 * 1024),
]

# Build sorted list of (header_bytes, sig_index) for fast scanning
_HEADER_TRIE: dict[bytes, list[int]] = {}
for _i, (_label, _ext, _hdr, _ftr, _maxsz) in enumerate(_SIGS):
    _HEADER_TRIE.setdefault(_hdr[:4], []).append(_i)


# ------------------------------------------------------------------ #
#  Carver                                                               #
# ------------------------------------------------------------------ #

class FileCarver:
    """
    Scan a byte stream for known file signatures and yield CarvedFile objects.

    Usage:
        carver = FileCarver()
        for carved in carver.carve_stream(data_bytes, base_offset=0):
            print(carved.label, carved.offset, carved.size)
    """

    def __init__(self, chunk_size: int = 4 * 1024 * 1024):
        self._chunk_size = chunk_size

    # ---------------------------------------------------------------- #
    #  Public API                                                        #
    # ---------------------------------------------------------------- #

    def carve_stream(self, data: bytes,
                     base_offset: int = 0,
                     progress_cb=None) -> Generator[CarvedFile, None, None]:
        """
        Scan data for all known signatures.
        progress_cb(offset, total) called periodically if provided.
        Yields CarvedFile objects in order of discovery.
        """
        total = len(data)
        view = memoryview(data)
        pos = 0

        while pos < total:
            if progress_cb and pos % (1024 * 1024) == 0:
                progress_cb(pos, total)

            # Check top 4 bytes against trie for fast rejection
            window = bytes(view[pos:pos + 4])
            candidates = _HEADER_TRIE.get(window, [])

            # Also check sub-matches (headers shorter than 4 bytes or different prefix)
            for prefix_len in (2, 3):
                sub = window[:prefix_len]
                candidates = candidates + _HEADER_TRIE.get(sub, [])

            best = None
            for idx in candidates:
                label, ext, hdr, footer, max_size = _SIGS[idx]
                if bytes(view[pos:pos + len(hdr)]) == hdr:
                    carved = self._extract(view, pos, hdr, footer, max_size,
                                           label, ext, base_offset)
                    if carved and (best is None or carved.size > best.size):
                        best = carved

            if best:
                yield best
                # Advance past this file to avoid re-matching its header
                pos += max(1, best.size)
            else:
                pos += 1

    def carve_file(self, image_path: str,
                   start_byte: int = 0,
                   progress_cb=None) -> Generator[CarvedFile, None, None]:
        """Carve directly from a (potentially large) file using chunked reading."""
        file_size = os.path.getsize(image_path)
        overlap = 16  # bytes of overlap between chunks to handle boundary headers

        with open(image_path, 'rb') as f:
            if start_byte:
                f.seek(start_byte)
            cumulative = start_byte
            tail = b''

            while True:
                chunk = f.read(self._chunk_size)
                if not chunk:
                    break
                block = tail + chunk
                for carved in self.carve_stream(block, base_offset=cumulative - len(tail),
                                                progress_cb=progress_cb):
                    # Clamp to actual file boundaries
                    if carved.offset >= cumulative - len(tail):
                        yield carved
                tail = block[-overlap:]
                cumulative += len(chunk)
                if progress_cb:
                    progress_cb(cumulative, file_size)

    # ---------------------------------------------------------------- #
    #  Extraction logic                                                  #
    # ---------------------------------------------------------------- #

    def _extract(self, view: memoryview, pos: int,
                 hdr: bytes, footer: bytes | None, max_size: int,
                 label: str, ext: str, base_offset: int) -> CarvedFile | None:
        if len(view) - pos < len(hdr):
            return None

        end = min(pos + max_size, len(view))

        if footer:
            fpos = bytes(view[pos + len(hdr): end]).find(footer)
            if fpos != -1:
                actual_end = pos + len(hdr) + fpos + len(footer)
            else:
                # No footer found — carve to max_size if header is strong enough
                actual_end = end
        else:
            # Footerless formats: use header-embedded size if parseable
            actual_end = self._infer_size(view, pos, hdr, ext, end)

        size = actual_end - pos
        if size < len(hdr) + 1:
            return None

        data = bytes(view[pos:actual_end])
        return CarvedFile(
            offset=base_offset + pos,
            size=size,
            label=label,
            extension=ext,
            data=data,
        )

    def _infer_size(self, view: memoryview, pos: int,
                    hdr: bytes, ext: str, max_end: int) -> int:
        """Try to read the file-format size field for footerless formats."""
        try:
            if ext == 'bmp' and len(view) - pos >= 6:
                import struct
                return pos + struct.unpack_from('<I', view, pos + 2)[0]
            if ext in ('exe', 'elf'):
                return self._find_pe_elf_end(view, pos, max_end)
        except Exception:
            pass
        return max_end

    def _find_pe_elf_end(self, view: memoryview, pos: int, max_end: int) -> int:
        """Heuristic: find next MZ/ELF header after pos as a size bound."""
        search = bytes(view[pos + 2: min(pos + 10 * 1024 * 1024, max_end)])
        next_mz = search.find(b'MZ')
        if next_mz > 0:
            return pos + 2 + next_mz
        return min(pos + 10 * 1024 * 1024, max_end)
