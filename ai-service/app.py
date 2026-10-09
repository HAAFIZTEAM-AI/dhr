from fastapi import FastAPI, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import json
from analyzers.text_analyzer import analyze_text
from analyzers.website_analyzer import analyze_website
from analyzers.voice_analyzer import analyze_voice
from analyzers.phone_analyzer import analyze_phone
from analyzers.image_analyzer import analyze_image
from dotenv import load_dotenv

load_dotenv()
app = FastAPI(title="HAAFIZ AI Service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class TextRequest(BaseModel):
    text: str
    language: str = "auto"

class WebsiteRequest(BaseModel):
    url: str

class VoiceRequest(BaseModel):
    audio_base64: str
    language: str = "auto"

class PhoneRequest(BaseModel):
    phone_number: str

class ImageRequest(BaseModel):
    image_base64: str

@app.post("/analyze/text")
async def text_analysis(req: TextRequest):
    result = analyze_text(req.text, req.language)   # No await
    return result

@app.post("/analyze/website")
async def website_analysis(req: WebsiteRequest):
    result = await analyze_website(req.url)          # Keep await (async function)
    return result

@app.post("/analyze/voice")
async def voice_analysis(req: VoiceRequest):
    result = analyze_voice(req.audio_base64, req.language)   # No await
    return result

@app.post("/analyze/phone")
async def phone_analysis(req: PhoneRequest):
    result = analyze_phone(req.phone_number)          # No await
    return result

@app.post("/analyze/image")
async def image_analysis(req: ImageRequest):
    result = analyze_image(req.image_base64)          # No await
    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 5001)))