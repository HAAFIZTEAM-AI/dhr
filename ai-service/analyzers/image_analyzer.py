import base64
import io
from PIL import Image
import pytesseract
from analyzers.text_analyzer import analyze_text

def analyze_image(image_base64):
    # Decode base64 image
    image_bytes = base64.b64decode(image_base64)
    image = Image.open(io.BytesIO(image_bytes))
    
    # Perform OCR
    try:
        text = pytesseract.image_to_string(image)
    except Exception as e:
        text = ""
    
    if not text.strip():
        return {
            "is_scam": False,
            "confidence": 0,
            "extracted_text": "",
            "risk_factors": [],
            "explanation": "No text could be extracted from the image."
        }
    
    # Run text analysis on extracted text
    result = analyze_text(text, 'auto')
    result['extracted_text'] = text
    return result