"""
Tests for src/ai/nlp/ner.py — SpaCyNER named entity extractor.

Interface tests use mocking (no real model needed).
Integration tests require spaCy + en_core_web_sm and are skipped when unavailable.
"""
import unittest
from unittest.mock import MagicMock, patch

try:
    import spacy
    SPACY_AVAILABLE = True
except ImportError:
    SPACY_AVAILABLE = False

from src.ai.nlp.ner import NamedEntity, SpaCyNER


def _make_mock_nlp(ents=None):
    """Return a mock spacy.load() result whose __call__ yields controlled .ents."""
    if ents is None:
        ents = []
    mock_doc = MagicMock()
    mock_doc.ents = ents
    mock_nlp = MagicMock(return_value=mock_doc)
    return mock_nlp


class TestSpaCyNERInterface(unittest.TestCase):
    """Mocked tests — no real model loading."""

    def setUp(self):
        # Reset class-level singleton so _load() fires fresh under mocks,
        # regardless of whether integration tests ran first in this session.
        SpaCyNER._nlp = None
        self.ner = SpaCyNER()

    # ------------------------------------------------------------------
    # 1. extract() always returns a list
    # ------------------------------------------------------------------
    def test_returns_list(self):
        with patch("spacy.load", return_value=_make_mock_nlp()):
            result = self.ner.extract("Some text about Alice.")
        self.assertIsInstance(result, list)

    # ------------------------------------------------------------------
    # 2. Empty string returns []
    # ------------------------------------------------------------------
    def test_empty_string_returns_empty(self):
        result = self.ner.extract("")
        self.assertEqual(result, [])

    # ------------------------------------------------------------------
    # 3. Whitespace-only returns []
    # ------------------------------------------------------------------
    def test_whitespace_only_returns_empty(self):
        result = self.ner.extract("   ")
        self.assertEqual(result, [])

    # ------------------------------------------------------------------
    # 4. Returned items are NamedEntity instances with required attrs
    # ------------------------------------------------------------------
    def test_result_items_are_named_entity(self):
        # Build a fake spaCy ent
        fake_ent = MagicMock()
        fake_ent.text = "Alice"
        fake_ent.label_ = "PERSON"
        fake_ent.start_char = 0
        fake_ent.end_char = 5

        mock_nlp = _make_mock_nlp(ents=[fake_ent])
        self.ner._nlp = None  # reset so _load() runs
        with patch("spacy.load", return_value=mock_nlp):
            result = self.ner.extract("Alice went to Paris.")

        self.assertTrue(len(result) >= 1)
        item = result[0]
        self.assertIsInstance(item, NamedEntity)
        self.assertTrue(hasattr(item, "text"))
        self.assertTrue(hasattr(item, "label"))
        self.assertTrue(hasattr(item, "start"))
        self.assertTrue(hasattr(item, "end"))

    # ------------------------------------------------------------------
    # 5. summarise() groups by label
    # ------------------------------------------------------------------
    def test_summarise_groups_by_label(self):
        ner = SpaCyNER()
        entities = [
            NamedEntity("Alice", "PERSON", 0, 5),
            NamedEntity("Bob",   "PERSON", 6, 9),
        ]
        result = ner.summarise(entities)
        self.assertIn("PERSON", result)
        self.assertEqual(sorted(result["PERSON"]), ["Alice", "Bob"])

    # ------------------------------------------------------------------
    # 6. summarise() deduplicates same entity
    # ------------------------------------------------------------------
    def test_summarise_deduplicates(self):
        ner = SpaCyNER()
        entities = [
            NamedEntity("Alice", "PERSON", 0, 5),
            NamedEntity("Alice", "PERSON", 10, 15),
        ]
        result = ner.summarise(entities)
        self.assertEqual(result["PERSON"].count("Alice"), 1)

    # ------------------------------------------------------------------
    # 7. summarise([]) returns {}
    # ------------------------------------------------------------------
    def test_summarise_empty_list(self):
        ner = SpaCyNER()
        result = ner.summarise([])
        self.assertEqual(result, {})

    # ------------------------------------------------------------------
    # 8. If spacy.load raises, extract() returns []
    # ------------------------------------------------------------------
    def test_exception_returns_empty(self):
        self.ner._nlp = None  # ensure _load() will run
        with patch("spacy.load", side_effect=RuntimeError("model not found")):
            result = self.ner.extract("Alice went to Paris.")
        self.assertEqual(result, [])


@unittest.skipUnless(SPACY_AVAILABLE, "spaCy not installed")
class TestSpaCyNERIntegration(unittest.TestCase):
    """Integration tests using the real en_core_web_sm model."""

    @classmethod
    def setUpClass(cls):
        cls.ner = SpaCyNER()

    # ------------------------------------------------------------------
    # 9. PERSON entity found
    # ------------------------------------------------------------------
    def test_person_entity_found(self):
        result = self.ner.extract("Alice Smith met Bob Jones yesterday.")
        labels = [e.label for e in result]
        self.assertIn("PERSON", labels)

    # ------------------------------------------------------------------
    # 10. ORG entity found
    # ------------------------------------------------------------------
    def test_org_entity_found(self):
        result = self.ner.extract("Google and Microsoft announced a partnership.")
        labels = [e.label for e in result]
        self.assertIn("ORG", labels)

    # ------------------------------------------------------------------
    # 11. GPE/LOC entity found
    # ------------------------------------------------------------------
    def test_location_entity_found(self):
        result = self.ner.extract("The meeting was held in London.")
        labels = [e.label for e in result]
        self.assertTrue(
            "GPE" in labels or "LOC" in labels,
            f"Expected GPE or LOC, got: {labels}"
        )

    # ------------------------------------------------------------------
    # 12. Very long string doesn't crash (truncated to max_chars)
    # ------------------------------------------------------------------
    def test_max_chars_respected(self):
        long_text = "Alice Smith works at Google. " * 7000  # ~200 k chars
        try:
            result = self.ner.extract(long_text)
            self.assertIsInstance(result, list)
        except Exception as exc:
            self.fail(f"extract() raised an exception on long input: {exc}")


if __name__ == "__main__":
    unittest.main()
