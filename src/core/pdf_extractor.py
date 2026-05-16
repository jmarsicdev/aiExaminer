"""
PDF text extraction using pdfminer.six.

Extracts plain text from PDF bytes so PDF evidence files feed into
NLP analysis, entity extraction, and full-text search.
"""
from __future__ import annotations
import io


class PDFExtractor:
    """Stateless PDF → text converter."""

    def extract(self, pdf_bytes: bytes) -> str:
        """
        Return all text extracted from pdf_bytes, or '' on failure.
        Pages are separated by a form-feed character.
        """
        try:
            from pdfminer.high_level import extract_text_to_fp
            from pdfminer.layout import LAParams
            buf = io.StringIO()
            extract_text_to_fp(
                io.BytesIO(pdf_bytes), buf,
                laparams=LAParams(), output_type='text', codec=None,
            )
            return buf.getvalue().strip()
        except Exception:
            return ""

    def extract_pages(self, pdf_bytes: bytes) -> list[str]:
        """Return a list of strings, one per PDF page. Empty list on failure."""
        try:
            from pdfminer.high_level import extract_pages as _ep
            from pdfminer.layout import LAParams, LTTextContainer
            pages = []
            for page_layout in _ep(io.BytesIO(pdf_bytes), laparams=LAParams()):
                page_text = "".join(
                    el.get_text()
                    for el in page_layout
                    if isinstance(el, LTTextContainer)
                )
                pages.append(page_text.strip())
            return pages
        except Exception:
            return []

    def page_count(self, pdf_bytes: bytes) -> int:
        """Return number of pages, or 0 on failure."""
        return len(self.extract_pages(pdf_bytes))
