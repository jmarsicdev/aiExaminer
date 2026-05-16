"""
Minimal NTFS parser for images where the VBR boot signature is missing/zeroed,
preventing pytsk3 and ntfs-3g from opening the volume.

Exposes the same list_directory() / read_file_content() interface as ImageParser
so the UI can use it as a drop-in fallback.
"""

import struct
import os
import datetime

_FILETIME_EPOCH_DELTA = 116444736000000000  # 100ns ticks from 1601 to 1970


def _filetime_to_str(ft):
    if not ft:
        return None
    try:
        ts = (ft - _FILETIME_EPOCH_DELTA) / 10_000_000
        return datetime.datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return None

# MFT reserved entry numbers
MFT_ENTRY_MFT      = 0
MFT_ENTRY_ROOT_DIR = 5

# NTFS attribute types
ATTR_STANDARD_INFO   = 0x10
ATTR_FILE_NAME       = 0x30
ATTR_DATA            = 0x80
ATTR_INDEX_ROOT      = 0x90
ATTR_INDEX_ALLOC     = 0xA0
ATTR_END             = 0xFFFFFFFF

# $FILE_NAME namespaces (0=POSIX, 1=Win32, 2=DOS, 3=Win32&DOS)
FNAME_NAMESPACE_POSIX = 0

# Index entry flags
IDX_ENTRY_HAS_SUBNODE = 0x01
IDX_ENTRY_LAST        = 0x02

# MFT entry flags
MFT_FLAG_IN_USE   = 0x01
MFT_FLAG_DIR      = 0x02


class RawNTFSParser:
    """
    Direct NTFS parser that reads from a raw image file (or ewf1 from ewfmount).
    partition_offset is the byte offset of the NTFS partition start in the image.
    """

    def __init__(self, image_path, partition_offset=0):
        self.image_path = image_path
        self.partition_offset = partition_offset
        self._f = open(image_path, 'rb')
        self._parse_vbr()
        # Cache MFT entry 0 ($MFT) to know where MFT data runs are (for large MFTs)
        self._mft_data_runs = None

    def close(self):
        self._f.close()

    def __del__(self):
        try:
            self._f.close()
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    #  Low-level I/O                                                       #
    # ------------------------------------------------------------------ #

    def _read_at(self, abs_offset, size):
        self._f.seek(abs_offset)
        return self._f.read(size)

    def _read_partition(self, rel_offset, size):
        return self._read_at(self.partition_offset + rel_offset, size)

    def _cluster_to_abs(self, lcn):
        return self.partition_offset + lcn * self.bytes_per_cluster

    # ------------------------------------------------------------------ #
    #  VBR                                                                 #
    # ------------------------------------------------------------------ #

    def _parse_vbr(self):
        vbr = self._read_partition(0, 512)
        self.bytes_per_sector   = struct.unpack_from('<H', vbr, 11)[0]
        self.sectors_per_cluster = vbr[13]
        self.bytes_per_cluster  = self.bytes_per_sector * self.sectors_per_cluster
        self.mft_lcn            = struct.unpack_from('<Q', vbr, 48)[0]
        self.mft_mirror_lcn     = struct.unpack_from('<Q', vbr, 56)[0]

        # These fields are signed bytes: positive = number of clusters,
        # negative = 2^|value| bytes (e.g. 0xF6 = -10 → 1024 bytes)
        raw = struct.unpack_from('<b', vbr, 64)[0]
        self.mft_record_size = raw * self.bytes_per_cluster if raw > 0 else (1 << abs(raw))

        raw_idx = struct.unpack_from('<b', vbr, 68)[0]
        self.index_block_size = raw_idx * self.bytes_per_cluster if raw_idx > 0 else (1 << abs(raw_idx))

    # ------------------------------------------------------------------ #
    #  MFT entry reading                                                   #
    # ------------------------------------------------------------------ #

    def _mft_entry_offset(self, entry_num):
        """Byte offset of MFT entry relative to partition start."""
        return self.mft_lcn * self.bytes_per_cluster + entry_num * self.mft_record_size

    def _read_mft_entry_raw(self, entry_num):
        offset = self.partition_offset + self._mft_entry_offset(entry_num)
        data = bytearray(self._read_at(offset, self.mft_record_size))
        if data[:4] != b'FILE':
            return None
        return self._apply_fixup(data)

    def _apply_fixup(self, data):
        """Apply NTFS update-sequence fixup to a FILE/INDX record."""
        usa_offset = struct.unpack_from('<H', data, 4)[0]
        usa_count  = struct.unpack_from('<H', data, 6)[0]
        if usa_offset == 0 or usa_count < 2:
            return data
        check_word = struct.unpack_from('<H', data, usa_offset)[0]
        for i in range(1, usa_count):
            sector_end = i * self.bytes_per_sector - 2
            if sector_end + 2 > len(data):
                break
            if struct.unpack_from('<H', data, sector_end)[0] != check_word:
                break  # fixup mismatch — record may be damaged
            replacement = struct.unpack_from('<H', data, usa_offset + i * 2)[0]
            struct.pack_into('<H', data, sector_end, replacement)
        return data

    # ------------------------------------------------------------------ #
    #  Attribute iteration                                                  #
    # ------------------------------------------------------------------ #

    def _iter_attrs(self, entry_data):
        """Yield (attr_type, attr_data) for every attribute in an MFT entry."""
        first_attr_offset = struct.unpack_from('<H', entry_data, 20)[0]
        pos = first_attr_offset
        while pos + 4 <= len(entry_data):
            attr_type = struct.unpack_from('<I', entry_data, pos)[0]
            if attr_type == ATTR_END:
                break
            attr_len = struct.unpack_from('<I', entry_data, pos + 4)[0]
            if attr_len < 8 or pos + attr_len > len(entry_data):
                break
            yield attr_type, entry_data[pos:pos + attr_len]
            pos += attr_len

    def _get_attr_content(self, attr_data):
        """Return raw bytes of a resident attribute's content, or None if non-resident."""
        non_resident = attr_data[8]
        if non_resident:
            return None
        content_len    = struct.unpack_from('<I', attr_data, 16)[0]
        content_offset = struct.unpack_from('<H', attr_data, 20)[0]
        return bytes(attr_data[content_offset:content_offset + content_len])

    def _get_attr_data_runs(self, attr_data):
        """Return (data_size, [(lcn, cluster_count), ...]) for a non-resident attribute."""
        non_resident = attr_data[8]
        if not non_resident:
            return None
        data_size   = struct.unpack_from('<Q', attr_data, 48)[0]
        runs_offset = struct.unpack_from('<H', attr_data, 32)[0]
        runs = self._parse_data_runs(attr_data[runs_offset:])
        return data_size, runs

    def _parse_data_runs(self, buf):
        """Decode NTFS data runs into list of (abs_lcn, cluster_count)."""
        runs = []
        pos = 0
        prev_lcn = 0
        while pos < len(buf) and buf[pos] != 0:
            header = buf[pos]; pos += 1
            len_len = header & 0x0F
            off_len = (header >> 4) & 0x0F
            if len_len == 0:
                break
            run_len = int.from_bytes(buf[pos:pos + len_len], 'little', signed=False)
            pos += len_len
            if off_len:
                run_off = int.from_bytes(buf[pos:pos + off_len], 'little', signed=True)
                pos += off_len
                prev_lcn += run_off
                runs.append((prev_lcn, run_len))
            # else: sparse run (lcn=0), skip
        return runs

    def _read_nonresident_attr(self, attr_data, max_bytes=None):
        """Read all data from a non-resident attribute via its data runs."""
        result = self._get_attr_data_runs(attr_data)
        if result is None:
            return b''
        data_size, runs = result
        if max_bytes is not None:
            data_size = min(data_size, max_bytes)
        chunks = []
        remaining = data_size
        for lcn, count in runs:
            if remaining <= 0:
                break
            byte_len = min(count * self.bytes_per_cluster, remaining)
            chunk = self._read_at(self._cluster_to_abs(lcn), byte_len)
            chunks.append(chunk)
            remaining -= byte_len
        return b''.join(chunks)

    # ------------------------------------------------------------------ #
    #  $STANDARD_INFORMATION (timestamps + flags)                           #
    # ------------------------------------------------------------------ #

    def _get_standard_info(self, entry_data):
        """Return (crtime, mtime, ctime, atime, flags) from $STANDARD_INFORMATION, or None."""
        for attr_type, attr_data in self._iter_attrs(entry_data):
            if attr_type == ATTR_STANDARD_INFO:
                content = self._get_attr_content(attr_data)
                if content and len(content) >= 32:
                    crtime = struct.unpack_from('<Q', content, 0)[0]
                    mtime  = struct.unpack_from('<Q', content, 8)[0]
                    ctime  = struct.unpack_from('<Q', content, 16)[0]
                    atime  = struct.unpack_from('<Q', content, 24)[0]
                    si_flags = struct.unpack_from('<I', content, 32)[0] if len(content) >= 36 else 0
                    return (
                        _filetime_to_str(crtime),
                        _filetime_to_str(mtime),
                        _filetime_to_str(ctime),
                        _filetime_to_str(atime),
                        si_flags,
                    )
        return None

    # ------------------------------------------------------------------ #
    #  File name parsing                                                    #
    # ------------------------------------------------------------------ #

    def _parse_filename_attr(self, content):
        """Return (name, parent_ref, is_dir_flag, file_size) from $FILE_NAME content."""
        if len(content) < 66:
            return None
        parent_ref = struct.unpack_from('<Q', content, 0)[0] & 0x0000FFFFFFFFFFFF
        alloc_size = struct.unpack_from('<Q', content, 40)[0]
        data_size  = struct.unpack_from('<Q', content, 48)[0]
        flags      = struct.unpack_from('<I', content, 56)[0]
        name_len   = content[64]
        namespace  = content[65]
        name_bytes = content[66:66 + name_len * 2]
        try:
            name = name_bytes.decode('utf-16-le', errors='replace')
        except Exception:
            name = repr(name_bytes)
        is_dir = bool(flags & 0x10000000)
        return name, parent_ref, is_dir, data_size

    # ------------------------------------------------------------------ #
    #  Directory listing via index                                          #
    # ------------------------------------------------------------------ #

    def _list_index_root(self, idx_root_content):
        """Yield (file_ref, name, is_dir, size) from $INDEX_ROOT resident content."""
        # Header: attr_type(4) collation(4) block_size(4) clusters_per_block(1) pad(3)
        # Then index header: entries_offset(4) end_used(4) end_alloc(4) flags(1) pad(3)
        # entries start at index_header_offset + entries_offset
        ih_offset = 16  # after the 16-byte index root header
        entries_offset = struct.unpack_from('<I', idx_root_content, ih_offset)[0]
        entries_start  = ih_offset + entries_offset
        yield from self._iter_index_entries(idx_root_content, entries_start)

    def _iter_index_entries(self, buf, pos):
        while pos + 16 <= len(buf):
            file_ref   = struct.unpack_from('<Q', buf, pos)[0]
            entry_len  = struct.unpack_from('<H', buf, pos + 8)[0]
            fname_len  = struct.unpack_from('<H', buf, pos + 10)[0]
            flags      = struct.unpack_from('<I', buf, pos + 12)[0]

            if flags & IDX_ENTRY_LAST:
                break
            if entry_len < 16:
                break

            if fname_len >= 66:
                fname_data = buf[pos + 16: pos + 16 + fname_len]
                parsed = self._parse_filename_attr(fname_data)
                if parsed:
                    name, _, is_dir, size = parsed
                    mft_num = file_ref & 0x0000FFFFFFFFFFFF
                    if name and name not in ('.', '..') and not name.startswith('$'):
                        yield mft_num, name, is_dir, size
            pos += entry_len

    def _list_dir_entries(self, mft_num):
        """Yield (mft_num, name, is_dir, size) for all entries in directory mft_num."""
        entry = self._read_mft_entry_raw(mft_num)
        if entry is None:
            return

        index_root_content = None
        index_alloc_attr   = None

        for attr_type, attr_data in self._iter_attrs(entry):
            if attr_type == ATTR_INDEX_ROOT:
                index_root_content = self._get_attr_content(attr_data)
            elif attr_type == ATTR_INDEX_ALLOC:
                index_alloc_attr = attr_data

        seen_names = set()

        def dedup(gen):
            for item in gen:
                if item[1] not in seen_names:
                    seen_names.add(item[1])
                    yield item

        if index_root_content:
            yield from dedup(self._list_index_root(index_root_content))

        if index_alloc_attr:
            yield from dedup(self._list_index_alloc(index_alloc_attr))

    def _list_index_alloc(self, attr_data):
        """Yield (mft_num, name, is_dir, size) from $INDEX_ALLOCATION data runs."""
        result = self._get_attr_data_runs(attr_data)
        if result is None:
            return
        _, runs = result
        for lcn, count in runs:
            for block_num in range(count):
                block_off = self._cluster_to_abs(lcn + block_num)
                raw = bytearray(self._read_at(block_off, self.index_block_size))
                if raw[:4] != b'INDX':
                    continue
                raw = self._apply_fixup(raw)
                # INDX block: signature(4) usa_off(2) usa_count(2) lsn(8) vcn(8) index_header(28...)
                ih_offset = 24
                entries_offset = struct.unpack_from('<I', raw, ih_offset)[0]
                entries_start  = ih_offset + entries_offset
                yield from self._iter_index_entries(raw, entries_start)

    # ------------------------------------------------------------------ #
    #  Path resolution                                                      #
    # ------------------------------------------------------------------ #

    def _build_mft_name_map(self):
        """Build {mft_num: (name, parent_mft_num, is_dir)} from the first 10k MFT entries."""
        name_map = {5: ('', 5, True)}  # root dir
        for entry_num in range(6, 10000):
            try:
                entry = self._read_mft_entry_raw(entry_num)
                if entry is None:
                    continue
                flags = struct.unpack_from('<H', entry, 22)[0]
                if not (flags & MFT_FLAG_IN_USE):
                    continue
                for attr_type, attr_data in self._iter_attrs(entry):
                    if attr_type == ATTR_FILE_NAME:
                        content = self._get_attr_content(attr_data)
                        if content is None:
                            continue
                        parsed = self._parse_filename_attr(content)
                        if parsed:
                            name, parent_ref, is_dir, size = parsed
                            if name and not name.startswith('$'):
                                name_map[entry_num] = (name, parent_ref, is_dir)
                            break
            except Exception:
                continue
        return name_map

    def _resolve_path(self, path):
        """Return MFT number for a given virtual path, or None."""
        if path in ('/', ''):
            return MFT_ENTRY_ROOT_DIR
        parts = [p for p in path.replace('\\', '/').split('/') if p]
        current_mft = MFT_ENTRY_ROOT_DIR
        for part in parts:
            found = None
            for mft_num, name, is_dir, size in self._list_dir_entries(current_mft):
                if name.lower() == part.lower():
                    found = mft_num
                    break
            if found is None:
                return None
            current_mft = found
        return current_mft

    # ------------------------------------------------------------------ #
    #  Public interface (matches ImageParser / LocalParser)                 #
    # ------------------------------------------------------------------ #

    def list_directory(self, path='/', inode=None):
        mft_num = inode if inode is not None else self._resolve_path(path)
        if mft_num is None:
            return
        seen = set()
        try:
            for child_mft, name, is_dir, size in self._list_dir_entries(mft_num):
                if name in seen:
                    continue
                seen.add(name)
                entry_path = path.rstrip('/') + '/' + name

                # Fetch timestamps + deletion status from child MFT entry
                crtime = mtime = ctime = atime = None
                is_deleted = False
                try:
                    child_entry = self._read_mft_entry_raw(child_mft)
                    if child_entry:
                        entry_flags = struct.unpack_from('<H', child_entry, 22)[0]
                        is_deleted  = not bool(entry_flags & MFT_FLAG_IN_USE)
                        si = self._get_standard_info(child_entry)
                        if si:
                            crtime, mtime, ctime, atime, _ = si
                except Exception:
                    pass

                yield {
                    'name':       name,
                    'type':       'Folder' if is_dir else 'File',
                    'size':       size,
                    'path':       entry_path,
                    'inode':      child_mft,
                    'crtime':     crtime,
                    'mtime':      mtime,
                    'atime':      atime,
                    'ctime':      ctime,
                    'is_deleted': is_deleted,
                }
        except Exception as e:
            print(f'RawNTFSParser: error listing {path}: {e}')

    def read_file_content(self, path):
        mft_num = self._resolve_path(path)
        if mft_num is None:
            return None
        try:
            entry = self._read_mft_entry_raw(mft_num)
            if entry is None:
                return None
            for attr_type, attr_data in self._iter_attrs(entry):
                if attr_type == ATTR_DATA:
                    content = self._get_attr_content(attr_data)
                    if content is not None:
                        return content
                    return self._read_nonresident_attr(attr_data)
            return None
        except Exception as e:
            print(f'RawNTFSParser: error reading {path}: {e}')
            return None
