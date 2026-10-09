import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Shield, AlertTriangle, XCircle, Volume2, Flag, Bell } from 'lucide-react';
import ConfidenceBar from './ConfidenceBar';
import RiskFactorTag from './RiskFactorTag';
import { useLanguage } from '../../context/LanguageContext';
import { useAuth } from '../../context/AuthContext';
import { useGamification } from '../../context/GamificationContext';
import { useFamily } from '../../context/FamilyContext';
import api from '../../utils/api';

export default function ScanResult({ result, inputText = '', inputType = 'text' }) {
  const { t, lang } = useLanguage();
  const { token } = useAuth();
  const { awardPoints } = useGamification();
  const { sendAlert } = useFamily();
  const [reporting, setReporting] = useState(false);
  const [reportDone, setReportDone] = useState(false);
  const [reportType, setReportType] = useState('private');
  const [sendingFamilyAlert, setSendingFamilyAlert] = useState(false);
  const [familyAlertSent, setFamilyAlertSent] = useState(false);

  const isScam = result.is_scam;
  const confidence = result.confidence;

  const getStatus = () => {
    if (confidence >= 60) return { label: t('result_scam'), color: 'text-rose-400', bg: 'bg-rose-500/10', border: 'border-rose-500/30', icon: XCircle };
    if (confidence >= 30) return { label: t('result_suspicious'), color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/30', icon: AlertTriangle };
    return { label: t('result_safe'), color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', icon: Shield };
  };

  const status = getStatus();
  const Icon = status.icon;

  const speak = () => {
    if ('speechSynthesis' in window) {
      const utterance = new SpeechSynthesisUtterance(result.explanation);
      utterance.lang = lang === 'ur' ? 'ur-PK' : 'en-US';
      window.speechSynthesis.speak(utterance);
    }
  };

  const handleReport = async () => {
    if (!token) {
      alert('Please login to report.');
      return;
    }
    setReporting(true);
    try {
      if (reportType === 'private') {
        await api.post('/reports', {
          content: inputText || '',
          content_type: inputType || 'text',
          result: isScam ? 'scam' : 'safe',
          confidence: confidence,
          is_scam: isScam,
          language: lang
        });
      } else {
        const title = prompt('Enter threat title:');
        if (!title) return;
        const description = prompt('Enter threat description:');
        await api.post('/threats', {
          title,
          description: description || inputText || '',
          type: inputType || 'text',
          severity: isScam ? 'high' : 'low',
          city: ''
        });
      }
      if (awardPoints) awardPoints(10, 'report_submitted', 'Report submitted');
      setReportDone(true);
      setTimeout(() => setReportDone(false), 3000);
    } catch (err) {
      console.error(err);
      alert('Report failed. Please try again.');
    } finally {
      setReporting(false);
    }
  };

  const handleSendFamilyAlert = async () => {
    if (!token) {
      alert('Please login to send family alert.');
      return;
    }
    setSendingFamilyAlert(true);
    try {
      const message = `Alert from family member: Scan result "${status.label}" with confidence ${confidence}%. ${result.explanation}`;
      const res = await sendAlert(message);
      if (res.success) {
        setFamilyAlertSent(true);
        setTimeout(() => setFamilyAlertSent(false), 3000);
        alert('Family alert sent successfully!');
      } else {
        alert(res.error || 'Failed to send family alert.');
      }
    } catch (err) {
      console.error(err);
      alert('Error sending family alert.');
    } finally {
      setSendingFamilyAlert(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.9, rotateX: -15 }}
      animate={{ opacity: 1, scale: 1, rotateX: 0 }}
      transition={{ type: 'spring', stiffness: 100, damping: 15 }}
      className={`mt-6 p-6 rounded-2xl border ${status.border} ${status.bg}`}
    >
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Icon className={`w-8 h-8 ${status.color}`} />
          <h3 className={`text-2xl font-bold ${status.color}`}>{status.label}</h3>
        </div>
        <button onClick={speak} className="text-slate-400 hover:text-white transition-colors">
          <Volume2 className="w-5 h-5" />
        </button>
      </div>

      <ConfidenceBar confidence={confidence} />

      {result.risk_factors && result.risk_factors.length > 0 && (
        <div className="mt-4">
          <h4 className="text-sm font-semibold text-slate-400 mb-2">{t('risk_factors')}</h4>
          <div className="flex flex-wrap gap-2">
            {result.risk_factors.map((factor, idx) => (
              <RiskFactorTag key={idx} factor={factor} />
            ))}
          </div>
        </div>
      )}

      <p className="mt-4 text-slate-300">{result.explanation}</p>
      <p className="mt-2 text-sm text-slate-400">{t('recommended_action')}: {result.recommended_action}</p>

      {/* Report Section */}
      <div className="mt-6 pt-4 border-t border-slate-700/50">
        <button
          onClick={handleReport}
          disabled={reporting || reportDone}
          className="btn-primary w-full flex items-center justify-center gap-2"
        >
          <Flag className="w-4 h-4" />
          {reportDone ? 'Reported!' : reporting ? 'Reporting...' : t('report_scam')}
        </button>
        {token && (
          <div className="mt-3 flex items-center justify-center gap-4 text-sm text-slate-400">
            <label className="flex items-center gap-1 cursor-pointer">
              <input
                type="radio"
                checked={reportType === 'private'}
                onChange={() => setReportType('private')}
                className="accent-emerald-500"
              />
              Private
            </label>
            <label className="flex items-center gap-1 cursor-pointer">
              <input
                type="radio"
                checked={reportType === 'public'}
                onChange={() => setReportType('public')}
                className="accent-rose-500"
              />
              Public Threat
            </label>
          </div>
        )}

        {/* Family Alert Button */}
        <button
          onClick={handleSendFamilyAlert}
          disabled={sendingFamilyAlert || familyAlertSent}
          className="btn-primary bg-cyan-600 hover:bg-cyan-700 w-full mt-2 flex items-center justify-center gap-2"
        >
          <Bell className="w-4 h-4" />
          {familyAlertSent ? 'Sent!' : sendingFamilyAlert ? 'Sending...' : 'Send Family Alert'}
        </button>
      </div>
    </motion.div>
  );
}