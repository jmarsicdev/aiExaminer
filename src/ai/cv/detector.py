from transformers import pipeline
from PIL import Image
import io

class CVDetector:
    def __init__(self):
        print("Initializing Computer Vision Object Detection pipeline...")
        # Using DEtection TRansformer (DETR)
        self.detector = pipeline("object-detection", model="facebook/detr-resnet-50")

    def analyze_image(self, image_bytes):
        """Detects objects in the provided image bytes."""
        if not image_bytes:
            return "No image data to analyze."

        try:
            image = Image.open(io.BytesIO(image_bytes))
            results = self.detector(image)
            
            output = "--- AI CV ANALYSIS ---\n"
            if not results:
                output += "No objects detected.\n"
            else:
                output += f"Detected {len(results)} objects:\n"
                for res in results:
                    output += f"- {res['label']} (Confidence: {res['score']:.4f})\n"
            
            return output
        except Exception as e:
            return f"CV Analysis Error: {e}"
