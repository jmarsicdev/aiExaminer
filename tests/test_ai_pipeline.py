import unittest
from unittest.mock import MagicMock, patch
from src.ai.nlp.analyzer import NLPAnalyzer
from src.ai.cv.detector import CVDetector

class TestAIPipeline(unittest.TestCase):

    @patch('src.ai.nlp.analyzer.pipeline')
    def test_nlp_analyzer(self, mock_pipeline):
        # Mock sentiment and generator
        mock_sentiment = MagicMock()
        mock_sentiment.return_value = [{'label': 'POSITIVE', 'score': 0.99}]
        
        mock_generator = MagicMock()
        mock_generator.return_value = [{'summary_text': 'This is a summary.'}]

        # The first call to pipeline is sentiment, second is summarization
        mock_pipeline.side_effect = [mock_sentiment, mock_generator]

        analyzer = NLPAnalyzer()
        # Reset class-level singleton so mock pipeline is used
        NLPAnalyzer._sentiment_pipe = None
        NLPAnalyzer._summary_pipe = None

        # Test short text (sentiment only, < 30 words)
        result = analyzer.analyze_text("Hello world")
        self.assertIn("POSITIVE", result)

        # Test long text (> 30 words, triggers summarization)
        long_text = " ".join(["word"] * 35)
        result = analyzer.analyze_text(long_text)
        self.assertIn("POSITIVE", result)
        self.assertIn("This is a summary.", result)

    @patch('src.ai.cv.detector.pipeline')
    @patch('PIL.Image.open')
    def test_cv_detector(self, mock_image_open, mock_pipeline):
        mock_detector = MagicMock()
        mock_detector.return_value = [{'label': 'cat', 'score': 0.95}]
        mock_pipeline.return_value = mock_detector
        
        detector = CVDetector()
        result = detector.analyze_image(b"fake_image_bytes")
        
        self.assertIn("Detected 1 objects", result)
        self.assertIn("cat", result)
        self.assertIn("0.9500", result)

if __name__ == '__main__':
    unittest.main()
