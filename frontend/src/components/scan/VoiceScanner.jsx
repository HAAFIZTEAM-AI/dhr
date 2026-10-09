import React, { useState } from 'react';
import { Mic, Square, Upload, Loader2, X } from 'lucide-react';
import api from '../../utils/api';
import ScanResult from './ScanResult';
import VoiceRecorder from '../features/VoiceRecorder';
import { useAuth } from '../../context/AuthContext';
import { useLanguage } from '../../context/LanguageContext';
import { useAlarm } from '../../context/AlarmContext';
import { useGamification } from '../../context/GamificationContext';

export default function VoiceScanner() {
  const { t, lang } = useLanguage();
  const { token } = useAuth();
  const { playAlarm } = useAlarm();
  const { awardPoints } = useGamification();
  const [audioBlob, setAudioBlob] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [transcript, setTranscript] = useState('');

  const handleAnalyze = async () => {
    if (!audioBlob) return;
    setLoading(true);
    setResult(null);
    try {
      const formData = new FormData();
      formData.append('audio', audioBlob, 'recording.wav');
      formData.append('language', lang);
      const res = await api.post('/voice/analyze', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setResult(res.data);
      setTranscript(res.data.transcript);
      if (res.data.is_scam) {
        playAlarm('scam');
        if (token) awardPoints(20, 'voice_scan', 'Voice scam detected');
      } else {
        playAlarm('safe');
        if (token) awardPoints(5, 'voice_scan', 'Voice scan completed');
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="glass-card p-6">
      <VoiceRecorder onRecordingComplete={setAudioBlob} />
      {audioBlob && (
        <div className="mt-4 flex items-center gap-2">
          <span className="text-sm text-slate-400">Recording ready</span>
          <button
            onClick={() => setAudioBlob(null)}
            className="text-rose-400 hover:text-rose-300"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}
      <button
        onClick={handleAnalyze}
        disabled={loading || !audioBlob}
        className="btn-primary w-full mt-4 flex items-center justify-center gap-2"
      >
        {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Mic className="w-5 h-5" />}
        {loading ? t('processing') : t('analyze')}
      </button>
      {transcript && (
        <div className="mt-4 p-4 bg-slate-800/50 rounded-xl">
          <p className="text-sm text-slate-400">Transcript:</p>
          <p className="text-slate-200">{transcript}</p>
        </div>
      )}
      {result && <ScanResult result={result} inputText={transcript} inputType="voice" />}
    </div>
  );
}