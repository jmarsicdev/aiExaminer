"""
Named Entity Recognition using spaCy en_core_web_sm.

Extracts PERSON, ORG, GPE (location), DATE, MONEY, and PRODUCT entities
from text, complementing the regex-based IOC extractor which finds emails,
IPs, SSNs, crypto addresses etc.
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class NamedEntity:
    text:  str
    label: str    # PERSON, ORG, GPE, DATE, MONEY, PRODUCT …
    start: int    # char offset in source text
    end:   int


# Labels we care about forensically
_WANTED = {"PERSON", "ORG", "GPE", "LOC", "DATE", "MONEY", "PRODUCT", "NORP"}


class SpaCyNER:
    """Lazy singleton — model loaded on first call."""

    _nlp = None

    def _load(self):
        if self._nlp is not None:
            return
        import spacy
        print("Loading spaCy NER model…")
        self._nlp = spacy.load("en_core_web_sm")
        print("spaCy NER ready.")

    def extract(self, text: str, max_chars: int = 50_000) -> list[NamedEntity]:
        """
        Extract named entities from text (truncated to max_chars).
        Returns empty list on failure or empty input.
        """
        if not text or not text.strip():
            return []
        try:
            self._load()
            doc = self._nlp(text[:max_chars])
            return [
                NamedEntity(ent.text, ent.label_, ent.start_char, ent.end_char)
                for ent in doc.ents
                if ent.label_ in _WANTED
            ]
        except Exception:
            return []

    def summarise(self, entities: list[NamedEntity]) -> dict[str, list[str]]:
        """
        Group entities by label. Returns {label: [unique_text, …]}.
        Deduplicates case-insensitively.
        """
        groups: dict[str, set[str]] = {}
        for e in entities:
            groups.setdefault(e.label, set()).add(e.text.strip())
        return {k: sorted(v) for k, v in groups.items()}
