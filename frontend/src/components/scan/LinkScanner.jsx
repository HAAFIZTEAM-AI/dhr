import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Search, Loader2, Globe } from 'lucide-react';
import api from '../../utils/api';
import ScanResult from './ScanResult';
import { useAuth } from '../../context/AuthContext';
import { useLanguage } from '../../context/LanguageContext';
import { useAlarm } from '../../context/AlarmContext';
import { useGamification } from '../../context/GamificationContext';

export default function LinkScanner() {
  const { t, lang } = useLanguage();
  const { token } = useAuth();
  const { playAlarm } = useAlarm();
  const { awardPoints } = useGamification();
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [screenshot, setScreenshot] = useState(null);

  const handleAnalyze = async () => {
    if (!url.trim()) return;
    setLoading(true);
    setResult(null);
    setScreenshot(null);
    try {
      const res = await api.post('/scan/analyze', { url, language: lang });
      setResult(res.data);
      if (res.data.module_results?.website?.screenshot_base64) {
        setScreenshot(res.data.module_results.website.screenshot_base64);
      }
      if (res.data.is_scam) {
        playAlarm('scam');
        if (token) awardPoints(15, 'website_scan', 'Scam website detected');
      } else {
        playAlarm('safe');
        if (token) awardPoints(5, 'website_scan', 'Website scan completed');
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="glass-card p-6">
      <div className="relative">
        <Globe className="absolute left-3 top-3 text-slate-500" />
        <input
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder={t('paste_link')}
          className="input-field pl-10 mb-4"
        />
      </div>
      <button
        onClick={handleAnalyze}
        disabled={loading || !url.trim()}
        className="btn-primary w-full flex items-center justify-center gap-2"
      >
        {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Search className="w-5 h-5" />}
        {loading ? t('crawling') : t('analyze')}
      </button>

      {screenshot && (
        <div className="mt-4">
          <img
            src={`data:image/png;base64,${screenshot}`}
            alt="Website screenshot"
            className="rounded-xl border border-slate-700 max-h-64 w-full object-cover"
          />
        </div>
      )}

      {result && <ScanResult result={result} inputText={url} inputType="url" />}
    </div>
  );
}