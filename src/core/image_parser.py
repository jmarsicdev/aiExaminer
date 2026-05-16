import pytsk3
import os
import datetime
import shutil
import subprocess
import tempfile
import multiprocessing


def _ts(unix_ts):
    """Convert unix timestamp int to ISO string, or None."""
    if not unix_ts:
        return None
    try:
        return datetime.datetime.utcfromtimestamp(unix_ts).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return None


def _list_dir_worker(image_path, path, inode, result_queue):
    """Subprocess worker: opens a fresh ImageParser and lists one directory.

    Runs in an isolated process so a SIGSEGV inside pytsk3's NTFS parser
    (ntfs_dinode_lookup → memcpy crash on corrupted MFT entries) cannot
    bring down the main application.
    """
    try:
        parser = ImageParser(image_path)
        entries = list(parser.list_directory(path, inode=inode))
        result_queue.put(('ok', entries))
        parser.close()
    except Exception as e:
        result_queue.put(('error', str(e)))


class EWFNotSupportedError(Exception):
    """Raised when pytsk3 lacks libewf support needed to open an E01 image."""
    def __init__(self, image_path):
        self.image_path = image_path
        super().__init__(
            f"pytsk3 was not compiled with libewf support and cannot open '{os.path.basename(image_path)}'.\n"
            "The app will attempt to auto-mount it with ewfmount."
        )


class _EwfMountedImg(pytsk3.Img_Info):
    """Raw-disk wrapper for an ewfmount-exposed image file.

    Reads from `path` (typically /mnt/ewf/ewf1) and transparently fixes a
    zeroed-out NTFS boot sector so that TSK's magic-byte check passes.
    """

    def __init__(self, path):
        self._fh = open(path, 'rb')
        self._fh.seek(0, 2)
        self._size = self._fh.tell()
        self._boot_offset = self._find_ntfs_boot()
        super().__init__()

    def _find_ntfs_boot(self):
        """Return the byte offset of the first sector that contains NTFS OEM ID."""
        for sector in range(5000):
            offset = sector * 512
            self._fh.seek(offset)
            data = self._fh.read(512)
            if len(data) >= 7 and data[3:7] == b'NTFS':
                return offset
        return None

    def read(self, offset, size):
        self._fh.seek(offset)
        data = bytearray(self._fh.read(size))
        if self._boot_offset is not None:
            bs = self._boot_offset
            if offset <= bs < offset + size:
                rel = bs - offset
                # Patch JMP instruction (bytes 0-2 of boot sector)
                if rel + 2 < len(data):
                    data[rel] = 0xEB
                    data[rel + 1] = 0x52
                    data[rel + 2] = 0x90
            if offset <= bs + 510 < offset + size:
                rel = (bs + 510) - offset
                # Patch boot signature (bytes 510-511)
                if rel + 1 < len(data):
                    data[rel] = 0x55
                    data[rel + 1] = 0xAA
        return bytes(data)

    def get_size(self):
        return self._size


class ImageParser:
    def __init__(self, image_path):
        self.image_path = image_path
        self.img_info = None
        self.fs_info = None
        self._ewf_mount_dir = None
        self._open_image()

    def _open_image(self):
        """Opens the image file and looks for a filesystem using aggressive discovery."""
        try:
            print(f"Attempting to open image: {self.image_path}")

            # 1. Open Image Info
            is_e01 = self.image_path.lower().endswith('.e01')
            if is_e01:
                ewf_type = getattr(pytsk3, 'TSK_IMG_TYPE_EWF_EWF', None)
                ewf_err = None
                if ewf_type is not None:
                    try:
                        self.img_info = pytsk3.Img_Info(self.image_path, ewf_type)
                    except Exception as e:
                        ewf_err = e
                        if "unsupported image type" not in str(e).lower():
                            raise
                if self.img_info is None:
                    # Try ewfmount fallback (requires FUSE + ewfmount on PATH)
                    ewfmount_bin = shutil.which('ewfmount')
                    if ewfmount_bin is None:
                        raise EWFNotSupportedError(self.image_path)
                    mount_dir = tempfile.mkdtemp(prefix='aiex_ewf_')
                    try:
                        result = subprocess.run(
                            [ewfmount_bin, self.image_path, mount_dir],
                            capture_output=True, timeout=30,
                        )
                        if result.returncode != 0:
                            raise EWFNotSupportedError(self.image_path)
                        raw_path = os.path.join(mount_dir, 'ewf1')
                        if not os.path.exists(raw_path):
                            raise EWFNotSupportedError(self.image_path)
                        self._ewf_mount_dir = mount_dir
                        self.img_info = _EwfMountedImg(raw_path)
                        print(f"Opened E01 via ewfmount: {raw_path}")
                    except EWFNotSupportedError:
                        shutil.rmtree(mount_dir, ignore_errors=True)
                        raise
                    except Exception as e:
                        shutil.rmtree(mount_dir, ignore_errors=True)
                        raise
            else:
                self.img_info = pytsk3.Img_Info(self.image_path)

            # 2. Try Standard Partition Discovery
            try:
                volume = pytsk3.Volume_Info(self.img_info)
                print(f"Detected partition table: {volume.info.vstype}")
                
                for part in volume:
                    desc = part.desc.decode('utf-8', errors='ignore')
                    offset = part.start * volume.info.block_size
                    
                    if desc.lower() in ["unallocated", "primary table", "guid partition table"]:
                        continue
                    
                    if self._try_open_fs(offset, desc):
                        return
            except Exception as vol_err:
                print(f"Partition table scan failed: {vol_err}")

            # 3. Aggressive Scan for Signatures
            print("Standard discovery failed. Starting aggressive signature scan...")
            # Scan first 5000 sectors (common range for boot sectors)
            for i in range(5000):
                offset = i * 512
                try:
                    # Quick check for signatures before calling expensive FS_Info
                    data = self.img_info.read(offset, 512)
                    if b"NTFS" in data or b"FAT" in data or b"EFI PART" in data:
                        if self._try_open_fs(offset, f"Discovered at sector {i}"):
                            return
                except:
                    continue

            # 4. Final Fallback (Offset 0)
            if self._try_open_fs(0, "Offset 0"):
                return

            raise Exception("Could not find a valid filesystem. The image may be encrypted or in an unsupported format.")
                
        except Exception as e:
            print(f"Critical error opening image: {e}")
            raise

    def _try_open_fs(self, offset, description):
        """Helper to attempt opening a filesystem at a specific offset."""
        try:
            print(f"  Attempting to open FS at {offset} ({description})...")
            self.fs_info = pytsk3.FS_Info(self.img_info, offset=offset)
            print(f"  SUCCESS: Opened filesystem at {offset}")
            return True
        except Exception as e:
            err_msg = str(e)
            if "encryption detected" in err_msg.lower():
                raise Exception(f"Encryption detected at offset {offset}. Decryption required.")
            return False

    def close(self):
        """Release resources and unmount any ewfmount FUSE mount."""
        self.fs_info = None
        self.img_info = None
        if self._ewf_mount_dir and os.path.isdir(self._ewf_mount_dir):
            fusermount = shutil.which('fusermount') or shutil.which('fusermount3')
            if fusermount:
                subprocess.run([fusermount, '-u', self._ewf_mount_dir],
                               capture_output=True, timeout=10)
            shutil.rmtree(self._ewf_mount_dir, ignore_errors=True)
            self._ewf_mount_dir = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def list_directory(self, path="/", inode=None):
        """Yields metadata for files/folders in the specified path.

        inode: if provided, open the directory by MFT inode number instead of
        path string. This bypasses pytsk3's path traversal and works reliably
        for deep/nested directories that path-based open sometimes fails on.
        """
        try:
            if inode is not None:
                directory = self.fs_info.open_dir(inode=inode)
            else:
                directory = self.fs_info.open_dir(path=path)
            for entry in directory:
                if entry.info.name is None:
                    continue
                name = entry.info.name.name.decode('utf-8', errors='replace')
                if name in [".", ".."]:
                    continue
                if entry.info.meta is None:
                    continue

                meta = entry.info.meta
                meta_type = meta.type

                entry_type = "File"
                if meta_type == pytsk3.TSK_FS_META_TYPE_DIR:
                    entry_type = "Folder"
                elif meta_type == pytsk3.TSK_FS_META_TYPE_LNK:
                    # NTFS junction points and symlinks — treat as expandable folders
                    entry_type = "Folder"

                flags = meta.flags if meta.flags else 0
                is_deleted = bool(flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)
                yield {
                    "name":       name,
                    "type":       entry_type,
                    "size":       meta.size,
                    "path":       os.path.join(path, name),
                    "inode":      meta.addr,
                    "crtime":     _ts(getattr(meta, 'crtime', None)),
                    "mtime":      _ts(getattr(meta, 'mtime',  None)),
                    "atime":      _ts(getattr(meta, 'atime',  None)),
                    "ctime":      _ts(getattr(meta, 'ctime',  None)),
                    "is_deleted": is_deleted,
                }
        except Exception as e:
            print(f"Error listing directory {path} (inode={inode}): {e}")
            return

    def list_directory_safe(self, path="/", inode=None, timeout=60):
        """Like list_directory but runs in a subprocess to survive pytsk3 SIGSEGV crashes.

        Returns a list of entry dicts (empty on crash/timeout).
        """
        ctx = multiprocessing.get_context('spawn')
        q = ctx.Queue()
        p = ctx.Process(
            target=_list_dir_worker,
            args=(self.image_path, path, inode, q),
            daemon=True,
        )
        p.start()
        try:
            status, data = q.get(timeout=timeout)
        except Exception:
            print(f"list_directory_safe: subprocess crashed or timed out (path={path!r}, inode={inode})")
            p.kill()
            p.join(timeout=2)
            return []
        p.join(timeout=5)
        if status == 'ok':
            return data
        print(f"list_directory_safe error: {data}")
        return []

    def read_file_content(self, path):
        """Reads and returns the raw bytes of a file from the image."""
        try:
            f = self.fs_info.open(path)
            # Read everything at once for now (simplified)
            return f.read_random(0, f.info.meta.size)
        except Exception as e:
            print(f"Error reading file {path}: {e}")
            return None
