"""
Pure-Python Windows Registry Hive (REGF) parser.

Parses NK (node key), VK (value key), and LF/LH/RI/LI lists without
any external dependencies. Handles registry hives extracted from forensic images.

Supports: NTUSER.DAT, SYSTEM, SOFTWARE, SAM, SECURITY, USRCLASS.DAT
"""

import struct
import datetime
from dataclasses import dataclass, field


# ------------------------------------------------------------------ #
#  Data types                                                           #
# ------------------------------------------------------------------ #

@dataclass
class RegValue:
    name:      str
    data_type: str   # 'REG_SZ', 'REG_DWORD', 'REG_BINARY', etc.
    data:      object


@dataclass
class RegKey:
    name:       str
    path:       str
    last_write: str
    values:     list[RegValue] = field(default_factory=list)
    subkeys:    list['RegKey'] = field(default_factory=list, repr=False)


_DATA_TYPES = {
    0: 'REG_NONE',
    1: 'REG_SZ',
    2: 'REG_EXPAND_SZ',
    3: 'REG_BINARY',
    4: 'REG_DWORD',
    5: 'REG_DWORD_BIG_ENDIAN',
    6: 'REG_LINK',
    7: 'REG_MULTI_SZ',
    8: 'REG_RESOURCE_LIST',
    9: 'REG_FULL_RESOURCE_DESCRIPTOR',
    10: 'REG_RESOURCE_REQUIREMENTS_LIST',
    11: 'REG_QWORD',
}

_FILETIME_DELTA = 116_444_736_000_000_000  # 100ns intervals from 1601 to 1970


# ------------------------------------------------------------------ #
#  Parser                                                               #
# ------------------------------------------------------------------ #

class RegistryParser:
    """
    Parse a Windows Registry hive from raw bytes.

    Usage:
        p = RegistryParser(hive_bytes)
        root = p.root
        for key in p.walk(root):
            print(key.path, [v.name for v in key.values])
    """

    def __init__(self, data: bytes):
        self._data = data
        self._base = 0x1000  # hive bins start at offset 0x1000
        self._validate()
        self.root: RegKey = self._read_root()

    def _validate(self):
        if self._data[:4] != b'regf':
            raise ValueError('Not a Windows registry hive (missing regf signature)')

    def _u16(self, off): return struct.unpack_from('<H', self._data, off)[0]
    def _u32(self, off): return struct.unpack_from('<I', self._data, off)[0]
    def _s32(self, off): return struct.unpack_from('<i', self._data, off)[0]
    def _u64(self, off): return struct.unpack_from('<Q', self._data, off)[0]

    def _abs(self, rel_off: int) -> int:
        """Convert a relative offset (from hive bins base) to absolute."""
        return self._base + rel_off

    def _cell(self, rel_off: int) -> bytes:
        """Read a cell at relative offset rel_off; cell size is the first int32."""
        abs_off = self._abs(rel_off)
        if abs_off + 4 > len(self._data):
            raise IndexError(f'Cell offset {rel_off:#x} out of bounds')
        size = self._s32(abs_off)
        cell_size = abs(size)
        if cell_size < 4:
            return b''
        return self._data[abs_off: abs_off + cell_size]

    def _filetime(self, off: int) -> str:
        ft = self._u64(off)
        if not ft:
            return '—'
        try:
            us = (ft - _FILETIME_DELTA) // 10
            dt = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=us)
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        except Exception:
            return str(ft)

    def _read_root(self) -> RegKey:
        # REGF header: root cell offset at offset 36
        root_off = self._u32(36)
        return self._read_nk(root_off, '')

    def _read_nk(self, rel_off: int, parent_path: str, depth: int = 0) -> RegKey:
        if depth > 50:
            return RegKey(name='[MAX DEPTH]', path=parent_path, last_write='')

        try:
            cell = self._cell(rel_off)
        except Exception:
            return RegKey(name='[read error]', path=parent_path, last_write='')

        if len(cell) < 80 or cell[4:6] != b'nk':
            return RegKey(name='[invalid]', path=parent_path, last_write='')

        base = self._abs(rel_off)

        flags         = self._u16(base + 6)
        last_write    = self._filetime(base + 8)
        subkey_count  = self._u32(base + 24)
        subkeys_off   = self._u32(base + 32)
        values_count  = self._u32(base + 40)
        values_off    = self._u32(base + 44)
        name_len      = self._u16(base + 72)
        name_off      = base + 76

        ascii_name = bool(flags & 0x20)
        try:
            raw_name = self._data[name_off: name_off + name_len]
            name = raw_name.decode('ascii' if ascii_name else 'utf-16-le',
                                   errors='replace')
        except Exception:
            name = '[decode error]'

        path = (parent_path + '\\' + name).lstrip('\\')

        # Read values
        values = []
        if values_count and values_off not in (0, 0xFFFFFFFF):
            values = self._read_values(values_off, values_count, base)

        # Read subkeys (lazy: only one level at a time)
        subkeys_rel = []
        if subkey_count and subkeys_off not in (0, 0xFFFFFFFF):
            subkeys_rel = self._read_subkey_list(subkeys_off)

        subkeys = [
            self._read_nk(sk_off, path, depth + 1)
            for sk_off in subkeys_rel[:1000]  # limit per node
        ]

        return RegKey(
            name=name,
            path=path,
            last_write=last_write,
            values=values,
            subkeys=subkeys,
        )

    def _read_subkey_list(self, list_off: int) -> list[int]:
        """Parse lf/lh/ri/li list; return list of NK cell relative offsets."""
        try:
            cell = self._cell(list_off)
        except Exception:
            return []
        if len(cell) < 6:
            return []

        sig = cell[4:6]
        count = struct.unpack_from('<H', cell, 6)[0]
        result = []

        if sig in (b'lf', b'lh'):
            for i in range(min(count, 2000)):
                entry_off = 8 + i * 8
                if entry_off + 4 > len(cell):
                    break
                nk_off = struct.unpack_from('<I', cell, entry_off)[0]
                result.append(nk_off)
        elif sig in (b'ri', b'li'):
            for i in range(min(count, 200)):
                entry_off = 8 + i * 4
                if entry_off + 4 > len(cell):
                    break
                sub_list_off = struct.unpack_from('<I', cell, entry_off)[0]
                result.extend(self._read_subkey_list(sub_list_off))
        return result

    def _read_values(self, values_list_off: int, count: int,
                     nk_abs: int) -> list[RegValue]:
        """Read the value list cell and parse each vk entry."""
        values = []
        try:
            list_cell = self._cell(values_list_off)
        except Exception:
            return values

        for i in range(min(count, 500)):
            ptr_off = 4 + i * 4
            if ptr_off + 4 > len(list_cell):
                break
            vk_off = struct.unpack_from('<I', list_cell, ptr_off)[0]
            v = self._read_vk(vk_off)
            if v:
                values.append(v)
        return values

    def _read_vk(self, rel_off: int) -> RegValue | None:
        try:
            cell = self._cell(rel_off)
        except Exception:
            return None
        if len(cell) < 24 or cell[4:6] != b'vk':
            return None

        base = self._abs(rel_off)
        name_len   = self._u16(base + 6)
        data_size  = self._u32(base + 8)
        data_off   = self._u32(base + 12)
        data_type  = self._u32(base + 16)
        vk_flags   = self._u16(base + 20)
        name_start = base + 24

        ascii_name = bool(vk_flags & 0x01)
        try:
            raw_name = self._data[name_start: name_start + name_len]
            name = raw_name.decode('ascii' if ascii_name else 'utf-16-le',
                                   errors='replace') if name_len else '(Default)'
        except Exception:
            name = '(Default)'

        type_str = _DATA_TYPES.get(data_type, f'0x{data_type:04X}')

        # Inline data: if high bit of data_size is set, data is in data_off itself
        inline = bool(data_size & 0x80000000)
        actual_size = data_size & 0x7FFFFFFF

        try:
            if inline or actual_size <= 4:
                raw = struct.pack('<I', data_off)[:actual_size]
            else:
                data_cell = self._cell(data_off)
                raw = data_cell[4: 4 + actual_size]

            parsed = _parse_value(raw, data_type)
        except Exception:
            parsed = '[read error]'

        return RegValue(name=name, data_type=type_str, data=parsed)

    # ---------------------------------------------------------------- #
    #  Public API                                                        #
    # ---------------------------------------------------------------- #

    def walk(self, key: RegKey | None = None):
        """Yield RegKey objects for every key in the hive (depth-first)."""
        if key is None:
            key = self.root
        yield key
        for sub in key.subkeys:
            yield from self.walk(sub)

    def find(self, path: str) -> RegKey | None:
        """Find a key by path (e.g. 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion')."""
        parts = [p for p in path.replace('/', '\\').split('\\') if p]
        cur = self.root
        for part in parts:
            match = next(
                (s for s in cur.subkeys if s.name.lower() == part.lower()),
                None,
            )
            if match is None:
                return None
            cur = match
        return cur


def _parse_value(raw: bytes, dtype: int) -> object:
    if dtype == 1 or dtype == 2:  # REG_SZ / REG_EXPAND_SZ
        try:
            return raw.rstrip(b'\x00').decode('utf-16-le', errors='replace')
        except Exception:
            return raw.hex()
    if dtype == 4:  # REG_DWORD
        return struct.unpack_from('<I', raw)[0] if len(raw) >= 4 else raw.hex()
    if dtype == 5:  # REG_DWORD_BIG_ENDIAN
        return struct.unpack_from('>I', raw)[0] if len(raw) >= 4 else raw.hex()
    if dtype == 11:  # REG_QWORD
        return struct.unpack_from('<Q', raw)[0] if len(raw) >= 8 else raw.hex()
    if dtype == 7:  # REG_MULTI_SZ
        try:
            return raw.rstrip(b'\x00').decode('utf-16-le', errors='replace').split('\x00')
        except Exception:
            return raw.hex()
    if dtype == 3:  # REG_BINARY
        return raw.hex() if len(raw) <= 64 else raw[:64].hex() + '…'
    return raw.hex() if len(raw) <= 64 else raw[:64].hex() + '…'


# ------------------------------------------------------------------ #
#  HTML renderer                                                        #
# ------------------------------------------------------------------ #

def render_html(root: RegKey, max_keys: int = 2000) -> str:
    parts = [
        '<style>'
        'details{margin-left:14px}'
        'summary{cursor:pointer;color:#4ecca3;font-size:12px;padding:2px 0}'
        'summary:hover{color:#fff}'
        '.vk{display:flex;gap:12px;font-size:11px;padding:1px 0;margin-left:16px}'
        '.vk-name{color:#aaa;min-width:180px}'
        '.vk-type{color:#666;min-width:100px}'
        '.vk-data{color:#e0e0e0;word-break:break-all}'
        '</style>'
    ]
    count = [0]

    def _render_key(k: RegKey, depth: int = 0):
        if count[0] >= max_keys:
            return
        count[0] += 1
        lw = f' <span style="color:#555;font-size:10px">[{k.last_write}]</span>' \
             if k.last_write and k.last_write != '—' else ''
        open_attr = ' open' if depth < 2 else ''
        parts.append(f'<details{open_attr}><summary>📁 {k.name}{lw}</summary>')

        # Values
        for v in k.values:
            dval = str(v.data)
            if len(dval) > 200:
                dval = dval[:197] + '…'
            dval = dval.replace('<', '&lt;').replace('>', '&gt;')
            parts.append(
                f'<div class="vk"><span class="vk-name">{v.name}</span>'
                f'<span class="vk-type">{v.data_type}</span>'
                f'<span class="vk-data">{dval}</span></div>'
            )

        # Subkeys
        for sub in k.subkeys:
            _render_key(sub, depth + 1)

        parts.append('</details>')

    _render_key(root)
    return ''.join(parts)
