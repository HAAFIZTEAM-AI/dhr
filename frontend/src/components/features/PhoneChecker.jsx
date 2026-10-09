import React, { useState } from 'react';
import { Phone, Search, AlertTriangle, CheckCircle } from 'lucide-react';
import api from '../../utils/api';
import { useLanguage } from '../../context/LanguageContext';
import { useAuth } from '../../context/AuthContext';

export default function PhoneChecker() {
  const { t } = useLanguage();
  const { token } = useAuth();
  const [phone, setPhone] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const checkNumber = async () => {
    if (!phone.trim()) return;
    setLoading(true);
    setResult(null);
    try {
      const res = await api.get(`/phone/${phone}`);
      setResult(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const reportNumber = async () => {
    if (!phone.trim() || !result) return;
    try {
      await api.post('/phone/report', { phone_number: phone, scam_type: 'unknown' });
      alert(t('report_scam') + ' submitted');
    } catch (err) {
      console.error(err);
    }
  };

  const riskColor = result?.risk_level === 'critical' || result?.risk_level === 'high' ? 'text-rose-400' : result?.risk_level === 'medium' ? 'text-amber-400' : 'text-emerald-400';

  return (
    <div className="glass-card p-6">
      <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
        <Phone className="w-5 h-5 text-cyan-400" /> {t('phone_check')}
      </h3>
      <div className="flex gap-2">
        <input
          type="tel"
          value={phone}
          onChange={(e) => setPhone(e.target.value)}
          placeholder={t('enter_number')}
          className="input-field flex-1"
        />
        <button onClick={checkNumber} disabled={loading} className="btn-primary">
          {loading ? '...' : <Search className="w-5 h-5" />}
        </button>
      </div>
      {result && (
        <div className="mt-4 p-4 bg-slate-800/50 rounded-xl">
          <div className="flex items-center gap-2 mb-2">
            {result.risk_level === 'critical' || result.risk_level === 'high' ? (
              <AlertTriangle className="w-5 h-5 text-rose-400" />
            ) : (
              <CheckCircle className="w-5 h-5 text-emerald-400" />
            )}
            <span className={`font-semibold ${riskColor}`}>
              {result.risk_level === 'critical' ? 'Critical' : result.risk_level === 'high' ? 'High Risk' : result.risk_level === 'medium' ? 'Medium Risk' : 'Low Risk'}
            </span>
          </div>
          <p className="text-sm text-slate-300">Reputation Score: {result.reputation_score}/100</p>
          <p className="text-sm text-slate-300">Report Count: {result.report_count}</p>
          {result.scam_types?.length > 0 && (
            <p className="text-sm text-slate-300">Scam Types: {result.scam_types.join(', ')}</p>
          )}
          {token && (
            <button onClick={reportNumber} className="mt-3 text-sm text-rose-400 hover:text-rose-300">
              {t('report_scam')}
            </button>
          )}
        </div>
      )}
    </div>
  );
}