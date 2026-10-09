import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Search, Loader2 } from 'lucide-react';
import api from '../../utils/api';
import ScanResult from './ScanResult';
import { useAuth } from '../../context/AuthContext';
import { useLanguage } from '../../context/LanguageContext';
import { useAlarm } from '../../context/AlarmContext';
import { useGamification } from '../../context/GamificationContext';

export default function TextScanner() {
  const { t, lang } = useLanguage();
  const { token } = useAuth();
  const { playAlarm } = useAlarm();
  const { awardPoints } = useGamification();
  const [text, setText] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleAnalyze = async () => {
    if (!text.trim()) return;
    setLoading(true);
    setResult(null);
    try {
      const res = await api.post('/scan/analyze', { text, language: lang });
      setResult(res.data);
      if (res.data.is_scam) {
        playAlarm('scam');
        if (token) awardPoints(10, 'first_scan', 'Scam detected');
      } else {
        playAlarm('safe');
        if (token) awardPoints(5, 'first_scan', 'Scan completed');
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="glass-card p-6">
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder={t('paste_text')}
        className="input-field min-h-[200px] mb-4"
      />
      <button
        onClick={handleAnalyze}
        disabled={loading || !text.trim()}
        className="btn-primary w-full flex items-center justify-center gap-2"
      >
        {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Search className="w-5 h-5" />}
        {loading ? t('analyzing') : t('analyze')}
      </button>

      {result && <ScanResult result={result} inputText={text} inputType="text" />}
    </div>
  );
}