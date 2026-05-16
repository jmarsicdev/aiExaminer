"""
Disk-backed thumbnail cache for the image gallery.

Thumbnails are stored as JPEG files in a cache directory keyed by
SHA-256 of the original image bytes. This avoids re-decoding large
images every time the gallery is opened.
"""
from __future__ import annotations
import hashlib
import io
import os


class ThumbnailCache:
    """
    Persistent thumbnail cache stored in cache_dir.
    Thread-safe for concurrent reads; writes use a temp-then-rename pattern.
    """

    def __init__(self, cache_dir: str):
        self._dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)

    def _key(self, image_bytes: bytes) -> str:
        return hashlib.sha256(image_bytes).hexdigest()

    def _path(self, key: str) -> str:
        return os.path.join(self._dir, f"{key}.jpg")

    def get(self, image_bytes: bytes) -> bytes | None:
        """Return cached thumbnail bytes, or None if not cached."""
        p = self._path(self._key(image_bytes))
        try:
            with open(p, "rb") as f:
                return f.read()
        except FileNotFoundError:
            return None

    def put(self, image_bytes: bytes, thumb_bytes: bytes) -> None:
        """Store thumb_bytes under the key derived from image_bytes."""
        key  = self._key(image_bytes)
        path = self._path(key)
        tmp  = path + ".tmp"
        try:
            with open(tmp, "wb") as f:
                f.write(thumb_bytes)
            os.replace(tmp, path)
        except Exception:
            try: os.unlink(tmp)
            except Exception: pass

    def get_or_make(
        self,
        image_bytes: bytes,
        width: int,
        height: int,
    ) -> bytes:
        """
        Return cached thumbnail or generate one scaled to (width, height).
        Falls back to original bytes if PIL is unavailable.
        """
        cached = self.get(image_bytes)
        if cached is not None:
            return cached

        try:
            from PIL import Image as PILImage
            img = PILImage.open(io.BytesIO(image_bytes)).convert("RGB")
            img.thumbnail((width, height), PILImage.LANCZOS)
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=75)
            thumb = buf.getvalue()
        except Exception:
            thumb = image_bytes

        self.put(image_bytes, thumb)
        return thumb

    def size(self) -> int:
        """Total number of cached thumbnails."""
        try:
            return sum(1 for f in os.listdir(self._dir) if f.endswith(".jpg"))
        except Exception:
            return 0

    def clear(self) -> int:
        """Delete all cached thumbnails. Returns count deleted."""
        deleted = 0
        for f in os.listdir(self._dir):
            if f.endswith(".jpg"):
                try:
                    os.unlink(os.path.join(self._dir, f))
                    deleted += 1
                except Exception:
                    pass
        return deleted
