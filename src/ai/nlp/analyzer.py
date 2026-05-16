from transformers import pipeline

class NLPAnalyzer:
    _sentiment_pipe = None
    _summary_pipe = None

    def _load(self):
        if self._sentiment_pipe is None:
            print("Loading NLP models (first run may download models)…")
            self._sentiment_pipe = pipeline(
                "sentiment-analysis",
                model="distilbert/distilbert-base-uncased-finetuned-sst-2-english"
            )
            self._summary_pipe = pipeline(
                "summarization",
                model="facebook/bart-large-cnn",
                max_length=130,
                min_length=30,
                do_sample=False,
            )
            print("NLP models ready.")

    def analyze_text(self, text: str) -> str:
        if not text or not text.strip():
            return "No text to analyze."
        self._load()
        try:
            sentiment = self._sentiment_pipe(text[:512])[0]
            summary_text = "Text too short for summarization."
            if len(text.split()) > 30:
                # BART max input is 1024 tokens; truncate words to be safe
                truncated = " ".join(text.split()[:800])
                result = self._summary_pipe(truncated)
                summary_text = result[0]["summary_text"]
            return (
                f"--- AI NLP ANALYSIS ---\n"
                f"Sentiment: {sentiment['label']} (Score: {sentiment['score']:.4f})\n"
                f"Summary: {summary_text}\n"
            )
        except Exception as e:
            return f"NLP Analysis Error: {e}"
