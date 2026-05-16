"""
Tests for src.utils.thumbnail_cache.ThumbnailCache
"""
import io
import tempfile
import unittest

from src.utils.thumbnail_cache import ThumbnailCache


def _make_jpeg(width: int = 8, height: int = 8, color: tuple = (100, 150, 200)) -> bytes:
    """Return a minimal valid JPEG as bytes using PIL."""
    from PIL import Image
    img = Image.new("RGB", (width, height), color=color)
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    return buf.getvalue()


class TestThumbnailCache(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.cache = ThumbnailCache(self._tmpdir)
        self.img_a = _make_jpeg(color=(10, 20, 30))
        self.img_b = _make_jpeg(color=(200, 100, 50))

    # 1. Fresh cache returns None for a miss
    def test_get_miss_returns_none(self):
        result = self.cache.get(self.img_a)
        self.assertIsNone(result)

    # 2. put then get returns the same bytes
    def test_put_and_get(self):
        thumb = b"fake_thumb_data"
        self.cache.put(self.img_a, thumb)
        result = self.cache.get(self.img_a)
        self.assertEqual(result, thumb)

    # 3. Two different images cache separately
    def test_different_images_different_keys(self):
        thumb_a = b"thumb_for_a"
        thumb_b = b"thumb_for_b"
        self.cache.put(self.img_a, thumb_a)
        self.cache.put(self.img_b, thumb_b)
        self.assertEqual(self.cache.get(self.img_a), thumb_a)
        self.assertEqual(self.cache.get(self.img_b), thumb_b)

    # 4. Same bytes returns same cached result
    def test_same_image_same_key(self):
        thumb = b"canonical_thumb"
        self.cache.put(self.img_a, thumb)
        img_a_copy = bytes(self.img_a)  # independent copy, same content
        self.assertEqual(self.cache.get(img_a_copy), thumb)

    # 5. get_or_make returns bytes
    def test_get_or_make_returns_bytes(self):
        result = self.cache.get_or_make(self.img_a, 64, 64)
        self.assertIsInstance(result, bytes)
        self.assertGreater(len(result), 0)

    # 6. Second call to get_or_make hits cache (put is called once)
    def test_get_or_make_caches_result(self):
        first = self.cache.get_or_make(self.img_a, 64, 64)
        # After first call, item must be in cache
        cached = self.cache.get(self.img_a)
        self.assertIsNotNone(cached)
        # Second call should return the same bytes (from cache)
        second = self.cache.get_or_make(self.img_a, 64, 64)
        self.assertEqual(first, second)
        # Cache size must still be 1 (not double-stored)
        self.assertEqual(self.cache.size(), 1)

    # 7. size() == 0 on fresh cache
    def test_size_empty(self):
        fresh = ThumbnailCache(tempfile.mkdtemp())
        self.assertEqual(fresh.size(), 0)

    # 8. size() == 1 after one put
    def test_size_after_put(self):
        self.cache.put(self.img_a, b"data")
        self.assertEqual(self.cache.size(), 1)

    # 9. clear() removes everything; size() returns 0 afterwards
    def test_clear_removes_all(self):
        self.cache.put(self.img_a, b"data_a")
        self.cache.put(self.img_b, b"data_b")
        self.cache.clear()
        self.assertEqual(self.cache.size(), 0)

    # 10. clear() returns the number of items deleted
    def test_clear_returns_count(self):
        self.cache.put(self.img_a, b"data_a")
        self.cache.put(self.img_b, b"data_b")
        count = self.cache.clear()
        self.assertEqual(count, 2)

    # 11. clear() does not raise if a cache file was removed externally
    def test_clear_tolerates_externally_deleted_file(self):
        import os, hashlib
        self.cache.put(self.img_a, b"data_a")
        # Manually delete the file before clear() runs
        key  = hashlib.sha256(self.img_a).hexdigest()
        path = os.path.join(self._tmpdir, f"{key}.jpg")
        os.unlink(path)
        # clear() must not raise; the already-gone file contributes 0 to count
        try:
            count = self.cache.clear()
        except Exception as exc:
            self.fail(f"clear() raised unexpectedly: {exc}")
        self.assertEqual(count, 0)

    # 12. get_or_make with corrupt image bytes falls back to original bytes
    def test_get_or_make_corrupt_falls_back(self):
        corrupt = b"\xff\xd8\xff" + b"\x00" * 10   # truncated JPEG header
        result = self.cache.get_or_make(corrupt, 64, 64)
        # Must return bytes (the fallback original) without raising
        self.assertIsInstance(result, bytes)
        self.assertGreater(len(result), 0)


if __name__ == "__main__":
    unittest.main()
