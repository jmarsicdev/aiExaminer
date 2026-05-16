"""
Tests for Task 1 (CLIP model upgrade) and Task 2 (NLPAnalyzer rewrite).
All tests use mocking — no real model downloads.
"""

import unittest
from unittest.mock import MagicMock, patch, call


# ---------------------------------------------------------------------------
# Task 1: CLIP model upgrade tests
# ---------------------------------------------------------------------------

class TestCLIPModelUpgrade(unittest.TestCase):

    def setUp(self):
        # Reset class-level singleton state before each test so lazy-load
        # triggers cleanly.
        from src.ai.cv.clip_search import CLIPImageSearcher
        CLIPImageSearcher._model = None
        CLIPImageSearcher._processor = None

    @patch("transformers.CLIPProcessor")
    @patch("transformers.CLIPModel")
    def test_uses_large_patch14_model_name(self, mock_model_cls, mock_processor_cls):
        """CLIPModel.from_pretrained must be called with 'large-patch14' in the model id."""
        from src.ai.cv.clip_search import CLIPImageSearcher
        searcher = CLIPImageSearcher()
        searcher._load()
        args, _ = mock_model_cls.from_pretrained.call_args
        self.assertIn("large-patch14", args[0])

    @patch("transformers.CLIPProcessor")
    @patch("transformers.CLIPModel")
    def test_uses_large_patch14_processor_name(self, mock_model_cls, mock_processor_cls):
        """CLIPProcessor.from_pretrained must be called with 'large-patch14' in the model id."""
        from src.ai.cv.clip_search import CLIPImageSearcher
        searcher = CLIPImageSearcher()
        searcher._load()
        args, _ = mock_processor_cls.from_pretrained.call_args
        self.assertIn("large-patch14", args[0])

    @patch("transformers.CLIPProcessor")
    @patch("transformers.CLIPModel")
    def test_searcher_lazy_loads_on_first_call(self, mock_model_cls, mock_processor_cls):
        """_model is None before _load(), set after, and not reloaded on second call."""
        from src.ai.cv.clip_search import CLIPImageSearcher

        searcher = CLIPImageSearcher()
        self.assertIsNone(searcher._model, "_model should be None before first use")

        # _load() sets _model and _processor via the mocked constructors
        searcher._load()
        self.assertIsNotNone(searcher._model, "_model should be set after _load()")

        # Second call must be a no-op (guard: if self._model is not None: return)
        first_ref = searcher._model
        searcher._load()
        self.assertIs(searcher._model, first_ref, "_load() must not reload if already loaded")


# ---------------------------------------------------------------------------
# Task 2: NLPAnalyzer rewrite tests
# ---------------------------------------------------------------------------

def _make_pipeline_mock():
    """
    Return a side_effect list for patching pipeline():
      first call  -> sentiment pipeline mock
      second call -> summary pipeline mock
    """
    mock_sentiment = MagicMock()
    mock_sentiment.return_value = [{"label": "POSITIVE", "score": 0.99}]

    mock_summary = MagicMock()
    mock_summary.return_value = [{"summary_text": "A mocked summary."}]

    return mock_sentiment, mock_summary


class TestNLPAnalyzer(unittest.TestCase):

    def setUp(self):
        # Reset singleton state before each test so _load() fires fresh.
        from src.ai.nlp.analyzer import NLPAnalyzer
        NLPAnalyzer._sentiment_pipe = None
        NLPAnalyzer._summary_pipe = None

    @patch("src.ai.nlp.analyzer.pipeline")
    def test_returns_string(self, mock_pipeline):
        mock_sentiment, mock_summary = _make_pipeline_mock()
        mock_pipeline.side_effect = [mock_sentiment, mock_summary]

        from src.ai.nlp.analyzer import NLPAnalyzer
        analyzer = NLPAnalyzer()
        result = analyzer.analyze_text("Hello world")
        self.assertIsInstance(result, str)

    def test_empty_text_no_crash(self):
        from src.ai.nlp.analyzer import NLPAnalyzer
        analyzer = NLPAnalyzer()
        result = analyzer.analyze_text("")
        self.assertEqual(result, "No text to analyze.")

    @patch("src.ai.nlp.analyzer.pipeline")
    def test_sentiment_in_output(self, mock_pipeline):
        mock_sentiment, mock_summary = _make_pipeline_mock()
        mock_pipeline.side_effect = [mock_sentiment, mock_summary]

        from src.ai.nlp.analyzer import NLPAnalyzer
        analyzer = NLPAnalyzer()
        result = analyzer.analyze_text("Hello world this is a test")
        self.assertIn("Sentiment:", result)

    @patch("src.ai.nlp.analyzer.pipeline")
    def test_summary_in_output(self, mock_pipeline):
        mock_sentiment, mock_summary = _make_pipeline_mock()
        mock_pipeline.side_effect = [mock_sentiment, mock_summary]

        from src.ai.nlp.analyzer import NLPAnalyzer
        analyzer = NLPAnalyzer()
        result = analyzer.analyze_text("Hello world this is a test")
        self.assertIn("Summary:", result)

    @patch("src.ai.nlp.analyzer.pipeline")
    def test_short_text_skips_summarization(self, mock_pipeline):
        """Text with fewer than 30 words should yield 'too short' in the summary line."""
        mock_sentiment, mock_summary = _make_pipeline_mock()
        mock_pipeline.side_effect = [mock_sentiment, mock_summary]

        from src.ai.nlp.analyzer import NLPAnalyzer
        analyzer = NLPAnalyzer()
        # Exactly 5 words — well under the 30-word threshold
        result = analyzer.analyze_text("short text under thirty words")
        self.assertIn("too short", result)
        mock_summary.assert_not_called()

    @patch("src.ai.nlp.analyzer.pipeline")
    def test_long_text_calls_summary_pipe(self, mock_pipeline):
        """Text with more than 30 words should invoke the summary pipeline."""
        mock_sentiment, mock_summary = _make_pipeline_mock()
        mock_pipeline.side_effect = [mock_sentiment, mock_summary]

        from src.ai.nlp.analyzer import NLPAnalyzer
        analyzer = NLPAnalyzer()
        long_text = " ".join(["word"] * 35)  # 35 words, above the 30-word threshold
        result = analyzer.analyze_text(long_text)
        mock_summary.assert_called_once()
        self.assertIn("A mocked summary.", result)


if __name__ == "__main__":
    unittest.main()
