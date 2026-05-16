"""
CLIP-based semantic image search for the gallery.

Uses openai/clip-vit-base-patch32 to embed both a text query and each image
into a shared vector space, then ranks images by cosine similarity.

Example queries (forensic):
  "weapon or gun", "document with text", "person's face",
  "money or cash", "drugs", "computer screen", "car or vehicle",
  "outdoor location", "handwritten note", "credit card"
"""

from __future__ import annotations
import io


class CLIPImageSearcher:
    """Lazy-loaded singleton — model is only downloaded on first search."""

    _model     = None
    _processor = None

    def _load(self):
        if self._model is not None:
            return
        from transformers import CLIPModel, CLIPProcessor
        print("Loading CLIP model (first run may download ~600 MB)…")
        self._model     = CLIPModel.from_pretrained("openai/clip-vit-large-patch14")
        self._processor = CLIPProcessor.from_pretrained("openai/clip-vit-large-patch14")
        print("CLIP model ready.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score_images(
        self,
        query: str,
        images: list[tuple[str, bytes]],
        progress_cb=None,
    ) -> list[tuple[str, float]]:
        """
        Score every (path, bytes) pair against the text query.

        Returns a list of (path, similarity) sorted descending.
        similarity is cosine similarity in [-1, 1]; typically 0.15–0.35 for
        a good match.

        progress_cb(done, total) is called after each image if provided.
        """
        self._load()
        import torch
        from PIL import Image as PILImage

        # Encode query text once
        text_inputs  = self._processor(text=[query], return_tensors="pt",
                                       padding=True, truncation=True)
        with torch.no_grad():
            text_out  = self._model.text_model(**{k: v for k, v in text_inputs.items()
                                                   if k in ('input_ids', 'attention_mask',
                                                             'position_ids')})
            text_feat = self._model.text_projection(text_out.pooler_output)
            text_feat = text_feat / text_feat.norm(dim=-1, keepdim=True)

        results: list[tuple[str, float]] = []
        total = len(images)

        for i, (path, data) in enumerate(images):
            try:
                img = PILImage.open(io.BytesIO(data)).convert("RGB")
                img_inputs = self._processor(images=img, return_tensors="pt")
                with torch.no_grad():
                    img_out  = self._model.vision_model(pixel_values=img_inputs['pixel_values'])
                    img_feat = self._model.visual_projection(img_out.pooler_output)
                    img_feat = img_feat / img_feat.norm(dim=-1, keepdim=True)
                sim = float((img_feat @ text_feat.T).item())
            except Exception:
                sim = 0.0
            results.append((path, sim))
            if progress_cb:
                progress_cb(i + 1, total)

        results.sort(key=lambda x: -x[1])
        return results
