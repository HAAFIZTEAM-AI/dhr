import base64
import tempfile
import os
import numpy as np
from functools import lru_cache
from pydub import AudioSegment
import whisper
from analyzers.text_analyzer import analyze_text

# Load model once (use "tiny" for speed; "base" for better accuracy)
@lru_cache(maxsize=1)
def get_model():
    return whisper.load_model("tiny")

model = get_model()

def convert_to_wav(input_path, output_path):
    """Convert any audio to 16kHz mono WAV using pydub (requires ffmpeg)."""
    try:
        audio = AudioSegment.from_file(input_path)
        audio = audio.set_frame_rate(16000).set_channels(1)
        audio.export(output_path, format='wav')
        return True
    except Exception:
        return False

def analyze_voice(audio_base64, language='auto'):
    # Decode base64 to a temp file. The incoming bytes may be in any
    # container the browser's MediaRecorder produced (webm, ogg, etc.),
    # not necessarily WAV, so we use a neutral suffix here rather than
    # hardcoding '.wav' (which previously made the conversion check below
    # always evaluate as "already WAV" and skip conversion entirely).
    audio_bytes = base64.b64decode(audio_base64)
    with tempfile.NamedTemporaryFile(delete=False, suffix='.input') as tmp:
        tmp.write(audio_bytes)
        tmp_path = tmp.name

    # Always normalize to 16kHz mono WAV for consistent transcription/tone analysis.
    new_path = tmp_path + '.wav'
    converted = convert_to_wav(tmp_path, new_path)
    os.unlink(tmp_path)
    if not converted:
        return {
            "transcript": "",
            "is_scam": False,
            "confidence": 0,
            "tone_analysis": {"urgency": 0, "authority": 0, "panic": 0},
            "matched_keywords": [],
            "language": language
        }
    tmp_path = new_path

    # Map language to supported Whisper codes
    supported = ['ur', 'en', 'sd', 'pa', 'bal']  # Whisper supports many, but these are relevant
    whisper_lang = None
    if language and language != 'auto' and language in supported:
        whisper_lang = language
    # For 'roman', we leave whisper_lang = None (auto-detect)

    try:
        result = model.transcribe(tmp_path, language=whisper_lang)
        transcript = result['text']
    except Exception as e:
        print(f"Transcription error: {e}")
        transcript = ""

    # Run text analysis (pass language or auto)
    text_analysis = analyze_text(transcript, language if language != 'auto' else 'auto')

    # Basic tone analysis (volume variance) - must happen before the temp
    # file is cleaned up, otherwise this always sees a missing file.
    urgency_score = 0
    try:
        audio_seg = AudioSegment.from_file(tmp_path) if os.path.exists(tmp_path) else None
        if audio_seg:
            samples = np.array(audio_seg.get_array_of_samples())
            if len(samples) > 0:
                volume_var = np.var(samples.astype(np.float64))
                urgency_score = min(100, int(volume_var / 1000000))
    except:
        pass
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)  # cleanup

    confidence = min(100, int(text_analysis['confidence'] * 0.8 + urgency_score * 0.2))
    is_scam = confidence >= 60

    return {
        "transcript": transcript,
        "is_scam": is_scam,
        "confidence": confidence,
        "tone_analysis": {
            "urgency": urgency_score,
            "authority": 50,
            "panic": 30
        },
        "matched_keywords": text_analysis.get('matched_keywords', []),
        "language": language
    }