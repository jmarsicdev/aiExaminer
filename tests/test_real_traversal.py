"""
Live traversal diagnostic — runs against real E01 images.

Usage:
    python tests/test_real_traversal.py [image_path]

If no path is given, tries both E01s in data/test_folder/.

Outputs:
  - Total dirs / files found
  - Maximum depth reached
  - Full directory listing (every folder path discovered)
  - Sample of deepest files found
  - Any paths that failed to expand (errors)
"""

import os
import sys
import shutil
import struct
import subprocess
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Parser bootstrap (mirrors main_window logic)
# ---------------------------------------------------------------------------

def open_parser(image_path: str):
    """
    Returns (parser, mount_dir_or_None).
    Tries ImageParser directly, falls back to ewfmount + ImageParser,
    then falls back to RawNTFSParser.
    Raises if all fail.
    """
    from src.core.image_parser import ImageParser, EWFNotSupportedError
    from src.core.ntfs_raw_parser import RawNTFSParser

    # 1. Direct open
    try:
        return ImageParser(image_path), None
    except EWFNotSupportedError:
        pass
    except Exception as e:
        print(f"  Direct open failed: {e}")

    # 2. ewfmount fallback
    print("  Trying ewfmount…")
    mount_dir = tempfile.mkdtemp(prefix='aiExaminer_diag_')
    result = subprocess.run(['ewfmount', image_path, mount_dir],
                            capture_output=True, text=True)
    if result.returncode != 0:
        shutil.rmtree(mount_dir, ignore_errors=True)
        raise RuntimeError(f"ewfmount failed: {result.stderr.strip()}")

    raw_image = os.path.join(mount_dir, 'ewf1')
    if not os.path.exists(raw_image):
        shutil.rmtree(mount_dir, ignore_errors=True)
        raise RuntimeError("ewf1 not found after ewfmount")

    try:
        parser = ImageParser(raw_image)
        return parser, mount_dir
    except Exception as e:
        print(f"  ImageParser on ewf1 failed: {e} — trying RawNTFSParser")

    # 3. RawNTFSParser fallback
    try:
        with open(raw_image, 'rb') as f:
            mbr = f.read(512)
        part_off = 0
        if mbr[510:512] == b'\x55\xaa':
            for i in range(4):
                ent = mbr[446 + i * 16: 462 + i * 16]
                lba = struct.unpack_from('<I', ent, 8)[0]
                if ent[4] and lba:
                    part_off = lba * 512
                    break
        parser = RawNTFSParser(raw_image, partition_offset=part_off)
        return parser, mount_dir
    except Exception as e:
        shutil.rmtree(mount_dir, ignore_errors=True)
        raise RuntimeError(f"All parsers failed: {e}")


# ---------------------------------------------------------------------------
# Recursive walker
# ---------------------------------------------------------------------------

class TraversalStats:
    def __init__(self):
        self.total_files = 0
        self.total_dirs  = 0
        self.max_depth   = 0
        self.all_dirs    : list[tuple[int, str]] = []  # (depth, path)
        self.deep_files  : list[tuple[int, str]] = []  # (depth, path)
        self.errors      : list[tuple[str, str]] = []  # (path, error)
        self.deleted     = 0


def walk(parser, path: str, stats: TraversalStats, depth: int = 0, inode=None):
    try:
        entries = list(parser.list_directory(path, inode=inode))
    except Exception as e:
        stats.errors.append((path, str(e)))
        return

    for entry in entries:
        if entry['type'] == 'Folder':
            stats.total_dirs += 1
            stats.all_dirs.append((depth + 1, entry['path']))
            if depth + 1 > stats.max_depth:
                stats.max_depth = depth + 1
            walk(parser, entry['path'], stats,
                 depth + 1, inode=entry.get('inode'))
        else:
            stats.total_files += 1
            if entry.get('is_deleted'):
                stats.deleted += 1
            if depth > 4:
                stats.deep_files.append((depth, entry['path']))


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_report(image_path: str, stats: TraversalStats, elapsed: float):
    sep = '─' * 72
    print(f"\n{sep}")
    print(f"  Image:       {image_path}")
    print(f"  Elapsed:     {elapsed:.1f}s")
    print(f"  Total dirs:  {stats.total_dirs}")
    print(f"  Total files: {stats.total_files}  ({stats.deleted} deleted/unallocated)")
    print(f"  Max depth:   {stats.max_depth}")
    print(f"  Errors:      {len(stats.errors)}")
    print(sep)

    print("\n── All directories discovered ──")
    if stats.all_dirs:
        for depth, path in sorted(stats.all_dirs, key=lambda x: x[1]):
            indent = '  ' * depth
            print(f"  {depth:2d}  {indent}{path}")
    else:
        print("  (none)")

    print(f"\n── Deep files (depth > 4) — {len(stats.deep_files)} total ──")
    for depth, path in sorted(stats.deep_files, key=lambda x: -x[0])[:40]:
        print(f"  depth {depth}: {path}")
    if not stats.deep_files:
        print("  (none found — directory traversal is still shallow)")

    if stats.errors:
        print(f"\n── Expansion errors ({len(stats.errors)}) ──")
        for path, err in stats.errors[:20]:
            print(f"  {path}: {err}")

    print(sep)

    # Verdict
    if stats.max_depth >= 6:
        print("  RESULT: PASS — deep traversal working (max depth >= 6)")
    elif stats.max_depth >= 3:
        print("  RESULT: PARTIAL — reaching some depth but not full tree")
    else:
        print("  RESULT: FAIL — traversal is shallow (max depth < 3)")
    print(sep)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_for_image(image_path: str):
    print(f"\n{'='*72}")
    print(f"  Testing: {image_path}")
    print(f"{'='*72}")

    mount_dir = None
    try:
        print("  Opening parser…")
        parser, mount_dir = open_parser(image_path)
        print(f"  Parser ready: {type(parser).__name__}")

        stats = TraversalStats()
        t0 = time.time()
        print("  Walking filesystem (this may take a minute for large images)…")
        walk(parser, '/', stats)
        elapsed = time.time() - t0

        print_report(image_path, stats, elapsed)
        return stats

    except Exception as e:
        print(f"  FATAL: {e}")
        return None
    finally:
        if mount_dir and os.path.isdir(mount_dir):
            subprocess.run(['fusermount', '-u', mount_dir], capture_output=True)
            shutil.rmtree(mount_dir, ignore_errors=True)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        images = sys.argv[1:]
    else:
        base = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'data', 'test_folder'
        )
        images = [
            os.path.join(base, 'ItemA_Evidence.E01'),
            os.path.join(base, 'GP2024.E01'),
        ]

    overall_pass = True
    for img in images:
        if not os.path.exists(img):
            print(f"Skipping (not found): {img}")
            continue
        stats = run_for_image(img)
        if stats is None or stats.max_depth < 3:
            overall_pass = False

    print(f"\nOverall: {'PASS' if overall_pass else 'FAIL'}")
    sys.exit(0 if overall_pass else 1)
