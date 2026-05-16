import os
import datetime


def _ts(unix_ts):
    if not unix_ts:
        return None
    try:
        return datetime.datetime.utcfromtimestamp(unix_ts).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return None


class LocalParser:
    """A parser that mimics ImageParser but works on a local directory."""
    def __init__(self, root_path):
        self.root_path = root_path

    def list_directory(self, path="/", inode=None):
        local_path = os.path.join(self.root_path, path.lstrip("/"))
        try:
            for entry in os.scandir(local_path):
                entry_type = "Folder" if entry.is_dir() else "File"
                stat = entry.stat(follow_symlinks=False)
                yield {
                    "name":       entry.name,
                    "type":       entry_type,
                    "size":       stat.st_size,
                    "path":       os.path.join(path, entry.name),
                    "inode":      stat.st_ino,
                    "crtime":     None,
                    "mtime":      _ts(stat.st_mtime),
                    "atime":      _ts(stat.st_atime),
                    "ctime":      _ts(stat.st_ctime),
                    "is_deleted": False,
                }
        except Exception as e:
            print(f"Error listing local directory {local_path}: {e}")
            return

    def read_file_content(self, path):
        local_path = os.path.join(self.root_path, path.lstrip("/"))
        try:
            with open(local_path, 'rb') as f:
                return f.read()
        except Exception as e:
            print(f"Error reading local file {local_path}: {e}")
            return None
