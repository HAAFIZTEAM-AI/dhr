import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Layers, Loader2, FileText, Image as ImageIcon, Mic } from 'lucide-react';
import api from '../../utils/api';
import ScanResult from './ScanResult';
import { useAuth } from '../../context/AuthContext';
import { useLanguage } from '../../context/LanguageContext';
import { useAlarm } from '../../context/AlarmContext';
import { useGamification } from '../../context/GamificationContext';

export default function MultimodalScanner() {
  const { t, lang } = useLanguage();
  const { token } = useAuth();
  const { playAlarm } = useAlarm();
  const { awardPoints } = useGamification();
  const [text, setText] = useState('');
  const [imageBase64, setImageBase64] = useState(null);
  const [audioBase64, setAudioBase64] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleTextFile = (file) => {
    const reader = new FileReader();
    reader.onload = (e) => setText(e.target.result);
    reader.readAsText(file);
  };

  const handleImageFile = (file) => {
    const reader = new FileReader();
    reader.onload = (e) => setImageBase64(e.target.result.split(',')[1]);
    reader.readAsDataURL(file);
  };

  const handleAudioFile = (file) => {
    const reader = new FileReader();
    reader.onload = (e) => setAudioBase64(e.target.result.split(',')[1]);
    reader.readAsDataURL(file);
  };

  const handleAnalyze = async () => {
    setLoading(true);
    setResult(null);
    try {
      const payload = {};
      if (text.trim()) payload.text = text;
      if (imageBase64) payload.image_base64 = imageBase64;
      if (audioBase64) payload.audio_base64 = audioBase64;
      payload.language = lang;
      const res = await api.post('/scan/analyze', payload);
      setResult(res.data);
      if (res.data.is_scam) {
        playAlarm('scam');
        if (token) awardPoints(25, 'multimodal_scan', 'Multimodal scam detected');
      } else {
        playAlarm('safe');
        if (token) awardPoints(10, 'multimodal_scan', 'Multimodal scan completed');
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="glass-card p-6">
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-slate-400 mb-2">
            <FileText className="inline-block w-4 h-4 mr-1" /> Text
          </label>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={t('paste_text')}
            className="input-field min-h-[100px]"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-400 mb-2">
            <ImageIcon className="inline-block w-4 h-4 mr-1" /> Image
          </label>
          <input
            type="file"
            accept="image/*"
            onChange={(e) => handleImageFile(e.target.files[0])}
            className="block w-full text-sm text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-xl file:border-0 file:bg-slate-700 hover:file:bg-slate-600 file:text-white"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-400 mb-2">
            <Mic className="inline-block w-4 h-4 mr-1" /> Audio
          </label>
          <input
            type="file"
            accept="audio/*"
            onChange={(e) => handleAudioFile(e.target.files[0])}
            className="block w-full text-sm text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-xl file:border-0 file:bg-slate-700 hover:file:bg-slate-600 file:text-white"
          />
        </div>
        <button
          onClick={handleAnalyze}
          disabled={loading || (!text.trim() && !imageBase64 && !audioBase64)}
          className="btn-primary w-full flex items-center justify-center gap-2"
        >
          {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Layers className="w-5 h-5" />}
          {loading ? t('processing') : t('analyze')}
        </button>
      </div>
      {result && <ScanResult result={result} inputText={text || ''} inputType="multimodal" />}
    </div>
  );
}