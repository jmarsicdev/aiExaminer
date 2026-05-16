"""
OCR text extraction from images using pytesseract + PIL.

Extracts visible text from image bytes so screenshots, scanned documents,
and photos of handwritten notes become searchable and feed into entity extraction.
"""
from __future__ import annotations
import io


class OCRExtractor:
    """Stateless — no model to load; pytesseract calls the system tesseract binary."""

    def extract(self, image_bytes: bytes, lang: str = "eng") -> str:
        """
        Return OCR text extracted from image_bytes, or '' on failure.

        lang: tesseract language code (default 'eng').
        """
        try:
            import pytesseract
            from PIL import Image as PILImage
            img = PILImage.open(io.BytesIO(image_bytes)).convert("RGB")
            text = pytesseract.image_to_string(img, lang=lang)
            return text.strip()
        except Exception:
            return ""

    def extract_with_confidence(self, image_bytes: bytes, lang: str = "eng") -> dict:
        """
        Return {'text': str, 'confidence': float} where confidence is mean
        word-level confidence 0-100 (or 0.0 on failure).
        """
        try:
            import pytesseract
            from PIL import Image as PILImage
            img = PILImage.open(io.BytesIO(image_bytes)).convert("RGB")
            data = pytesseract.image_to_data(img, lang=lang,
                                              output_type=pytesseract.Output.DICT)
            words = [w for w in data["text"] if w.strip()]
            confs = [c for c, w in zip(data["conf"], data["text"])
                     if w.strip() and c != -1]
            text = pytesseract.image_to_string(img, lang=lang).strip()
            confidence = sum(confs) / len(confs) if confs else 0.0
            return {"text": text, "words": len(words), "confidence": round(confidence, 1)}
        except Exception:
            return {"text": "", "words": 0, "confidence": 0.0}
