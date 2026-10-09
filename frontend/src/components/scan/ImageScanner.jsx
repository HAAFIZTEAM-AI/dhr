import React, { useState, useRef } from 'react';
import { motion } from 'framer-motion';
import { Upload, Image as ImageIcon, Loader2, X } from 'lucide-react';
import api from '../../utils/api';
import ScanResult from './ScanResult';
import { useAuth } from '../../context/AuthContext';
import { useLanguage } from '../../context/LanguageContext';
import { useAlarm } from '../../context/AlarmContext';
import { useGamification } from '../../context/GamificationContext';

export default function ImageScanner() {
  const { t, lang } = useLanguage();
  const { token } = useAuth();
  const { playAlarm } = useAlarm();
  const { awardPoints } = useGamification();
  const [imageBase64, setImageBase64] = useState(null);
  const [preview, setPreview] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const fileInputRef = useRef(null);

  const handleFile = (file) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      const base64 = e.target.result.split(',')[1];
      setImageBase64(base64);
      setPreview(e.target.result);
      setResult(null);
    };
    reader.readAsDataURL(file);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
  };

  const handleAnalyze = async () => {
    if (!imageBase64) return;
    setLoading(true);
    setResult(null);
    try {
      const res = await api.post('/scan/analyze', { image_base64: imageBase64, language: lang });
      setResult(res.data);
      if (res.data.is_scam) {
        playAlarm('scam');
        if (token) awardPoints(15, 'image_scan', 'Scam detected from image');
      } else {
        playAlarm('safe');
        if (token) awardPoints(5, 'image_scan', 'Image scan completed');
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="glass-card p-6">
      <div
        onDragOver={(e) => e.preventDefault()}
        onDrop={handleDrop}
        className="border-2 border-dashed border-slate-600 rounded-xl p-8 text-center cursor-pointer hover:border-emerald-400 transition-colors"
        onClick={() => fileInputRef.current?.click()}
      >
        {preview ? (
          <div className="relative">
            <img src={preview} alt="Uploaded" className="max-h-64 mx-auto rounded-lg" />
            <button
              onClick={(e) => { e.stopPropagation(); setPreview(null); setImageBase64(null); }}
              className="absolute top-2 right-2 bg-slate-900/80 rounded-full p-1"
            >
              <X className="w-5 h-5 text-white" />
            </button>
          </div>
        ) : (
          <div className="text-slate-400">
            <Upload className="w-12 h-12 mx-auto mb-4" />
            <p>{t('drag_drop')}</p>
          </div>
        )}
      </div>
      <input
        ref={fileInputRef}
        type="file"
        accept="image/*"
        className="hidden"
        onChange={(e) => handleFile(e.target.files[0])}
      />
      <button
        onClick={handleAnalyze}
        disabled={loading || !imageBase64}
        className="btn-primary w-full mt-4 flex items-center justify-center gap-2"
      >
        {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <ImageIcon className="w-5 h-5" />}
        {loading ? t('processing') : t('analyze')}
      </button>
      {result && <ScanResult result={result} inputText="" inputType="image" />}
    </div>
  );
}