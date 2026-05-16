"""
Unit tests for src/ai/cv/ocr.py — OCRExtractor.

pytesseract is mocked throughout so no real tesseract binary is required.
"""
from __future__ import annotations
import io
import sys
import types
import unittest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_jpeg() -> bytes:
    from PIL import Image as PILImage
    img = PILImage.new("RGB", (32, 32), color=(200, 200, 200))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    return buf.getvalue()


def _make_png() -> bytes:
    from PIL import Image as PILImage
    img = PILImage.new("RGB", (32, 32), color=(100, 150, 200))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _mock_pytesseract(image_to_string_return: str = "hello world",
                      image_to_data_return: dict | None = None) -> MagicMock:
    """Return a MagicMock that stands in for the pytesseract module."""
    if image_to_data_return is None:
        image_to_data_return = {"text": ["hello", "world"], "conf": [90, 85]}

    mock_pt = MagicMock()
    mock_pt.image_to_string.return_value = image_to_string_return
    mock_pt.image_to_data.return_value = image_to_data_return
    # pytesseract.Output.DICT is used as a kwarg value — just needs to be hashable
    mock_pt.Output.DICT = "dict"
    return mock_pt


# ---------------------------------------------------------------------------
# TestOCRExtractorInterface — mocked pytesseract
# ---------------------------------------------------------------------------

class TestOCRExtractorInterface(unittest.TestCase):
    """Tests that rely on mocked pytesseract (no binary needed)."""

    def _make_extractor(self):
        from src.ai.cv.ocr import OCRExtractor
        return OCRExtractor()

    # 1. result of extract() is a str
    def test_returns_string(self):
        extractor = self._make_extractor()
        mock_pt = _mock_pytesseract("some text")
        with patch.dict(sys.modules, {"pytesseract": mock_pt}):
            result = extractor.extract(_make_jpeg())
        self.assertIsInstance(result, str)

    # 2. corrupt/non-image bytes returns ''
    def test_empty_bytes_returns_empty(self):
        extractor = self._make_extractor()
        # Pass genuinely corrupt bytes — PIL.open will raise, returning ''
        result = extractor.extract(b"\x00\x01\x02corrupt")
        self.assertEqual(result, "")

    # 3. pytesseract returning '  hello  \n' gives 'hello'
    def test_strips_whitespace(self):
        extractor = self._make_extractor()
        mock_pt = _mock_pytesseract("  hello  \n")
        with patch.dict(sys.modules, {"pytesseract": mock_pt}):
            result = extractor.extract(_make_jpeg())
        self.assertEqual(result, "hello")

    # 4. dict has 'text' key
    def test_extract_with_confidence_has_text_key(self):
        extractor = self._make_extractor()
        mock_pt = _mock_pytesseract()
        with patch.dict(sys.modules, {"pytesseract": mock_pt}):
            result = extractor.extract_with_confidence(_make_jpeg())
        self.assertIn("text", result)

    # 5. dict has 'confidence' key
    def test_extract_with_confidence_has_confidence_key(self):
        extractor = self._make_extractor()
        mock_pt = _mock_pytesseract()
        with patch.dict(sys.modules, {"pytesseract": mock_pt}):
            result = extractor.extract_with_confidence(_make_jpeg())
        self.assertIn("confidence", result)

    # 6. dict has 'words' key
    def test_extract_with_confidence_has_words_key(self):
        extractor = self._make_extractor()
        mock_pt = _mock_pytesseract()
        with patch.dict(sys.modules, {"pytesseract": mock_pt}):
            result = extractor.extract_with_confidence(_make_jpeg())
        self.assertIn("words", result)

    # 7. on exception, text='' confidence=0.0
    def test_failure_returns_empty_dict_values(self):
        extractor = self._make_extractor()
        # corrupt bytes — PIL raises, extract_with_confidence catches and returns defaults
        result = extractor.extract_with_confidence(b"\x00corrupt")
        self.assertEqual(result["text"], "")
        self.assertEqual(result["confidence"], 0.0)


# ---------------------------------------------------------------------------
# TestOCRExtractorWithRealPIL — real PIL, mocked pytesseract
# ---------------------------------------------------------------------------

class TestOCRExtractorWithRealPIL(unittest.TestCase):
    """Tests that use real PIL to build images but mock pytesseract."""

    def _make_extractor(self):
        from src.ai.cv.ocr import OCRExtractor
        return OCRExtractor()

    # 8. JPEG processed correctly
    def test_jpeg_image_processed(self):
        extractor = self._make_extractor()
        mock_pt = _mock_pytesseract("test text")
        with patch.dict(sys.modules, {"pytesseract": mock_pt}):
            result = extractor.extract(_make_jpeg())
        self.assertEqual(result, "test text")

    # 9. PNG processed correctly
    def test_png_image_processed(self):
        extractor = self._make_extractor()
        mock_pt = _mock_pytesseract("test text")
        with patch.dict(sys.modules, {"pytesseract": mock_pt}):
            result = extractor.extract(_make_png())
        self.assertEqual(result, "test text")


if __name__ == "__main__":
    unittest.main()
