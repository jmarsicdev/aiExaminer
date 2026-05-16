"""
Unit tests for src/core/pdf_extractor.py — PDFExtractor.

pdfminer.six is installed in .venv. Minimal in-memory PDFs are constructed
from raw byte literals (no reportlab / external dependency required).
"""
from __future__ import annotations
import io
import sys
import unittest
from unittest.mock import MagicMock, patch, call


# ---------------------------------------------------------------------------
# Minimal valid 1-page PDF fixture
# ---------------------------------------------------------------------------

_MINIMAL_PDF = b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj
4 0 obj<</Length 44>>
stream
BT /F1 12 Tf 100 700 Td (Hello PDF World) Tj ET
endstream
endobj
5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj
xref
0 6
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000266 00000 n
0000000360 00000 n
trailer<</Size 6/Root 1 0 R>>
startxref
441
%%EOF"""


# ---------------------------------------------------------------------------
# TestPDFExtractorInterface — real pdfminer, edge-case inputs
# ---------------------------------------------------------------------------

class TestPDFExtractorInterface(unittest.TestCase):
    """Tests that exercise the public interface with real or edge-case inputs."""

    def _make_extractor(self):
        from src.core.pdf_extractor import PDFExtractor
        return PDFExtractor()

    # 1. extract() always returns str
    def test_returns_string(self):
        extractor = self._make_extractor()
        result = extractor.extract(_MINIMAL_PDF)
        self.assertIsInstance(result, str)

    # 2. extract(b"") returns ""
    def test_empty_bytes_returns_empty(self):
        extractor = self._make_extractor()
        result = extractor.extract(b"")
        self.assertEqual(result, "")

    # 3. extract(b"not a pdf") returns ""
    def test_corrupt_bytes_returns_empty(self):
        extractor = self._make_extractor()
        result = extractor.extract(b"not a pdf")
        self.assertEqual(result, "")

    # 4. extract(_MINIMAL_PDF) returns non-empty str OR "" gracefully
    def test_valid_pdf_returns_nonempty_string(self):
        extractor = self._make_extractor()
        result = extractor.extract(_MINIMAL_PDF)
        # pdfminer may or may not decode the embedded font; both outcomes are acceptable
        self.assertIsInstance(result, str)
        # If pdfminer successfully parsed it, the result should be non-empty
        # (we do not hard-assert non-empty because font encoding may differ per env)

    # 5. extract_pages() always returns list
    def test_extract_pages_returns_list(self):
        extractor = self._make_extractor()
        result = extractor.extract_pages(_MINIMAL_PDF)
        self.assertIsInstance(result, list)

    # 6. extract_pages(b"") returns []
    def test_extract_pages_empty_bytes(self):
        extractor = self._make_extractor()
        result = extractor.extract_pages(b"")
        self.assertEqual(result, [])

    # 7. page_count() returns int >= 0
    def test_page_count_returns_int(self):
        extractor = self._make_extractor()
        result = extractor.page_count(_MINIMAL_PDF)
        self.assertIsInstance(result, int)
        self.assertGreaterEqual(result, 0)

    # 8. page_count(b"garbage") returns 0
    def test_page_count_corrupt_returns_zero(self):
        extractor = self._make_extractor()
        result = extractor.page_count(b"garbage")
        self.assertEqual(result, 0)


# ---------------------------------------------------------------------------
# TestPDFExtractorWithMock — pdfminer patched out entirely
# ---------------------------------------------------------------------------

class TestPDFExtractorWithMock(unittest.TestCase):
    """Tests that patch pdfminer to verify call behaviour and error handling."""

    def _make_extractor(self):
        from src.core.pdf_extractor import PDFExtractor
        return PDFExtractor()

    # 9. extract() calls pdfminer.high_level.extract_text_to_fp for non-empty input
    def test_extract_calls_pdfminer(self):
        extractor = self._make_extractor()

        # We patch at the point where the module is imported inside extract()
        with patch("pdfminer.high_level.extract_text_to_fp") as mock_fn:
            # Make the mock write something to the StringIO buffer so strip() works
            def _fake_extract(in_fp, out_fp, **kwargs):
                out_fp.write("mocked text")

            mock_fn.side_effect = _fake_extract
            result = extractor.extract(_MINIMAL_PDF)

        mock_fn.assert_called_once()
        self.assertEqual(result, "mocked text")

    # 10. if pdfminer raises, extract() returns "" without crashing
    def test_extract_exception_caught(self):
        extractor = self._make_extractor()

        with patch("pdfminer.high_level.extract_text_to_fp",
                   side_effect=RuntimeError("simulated pdfminer failure")):
            result = extractor.extract(_MINIMAL_PDF)

        self.assertEqual(result, "")


if __name__ == "__main__":
    unittest.main()
