import React from 'react';
import { useLanguage } from '../../context/LanguageContext';

export default function ElderModeToggle({ enabled, onChange }) {
  const { t } = useLanguage();
  return (
    <div className="flex items-center justify-between p-4 glass-card">
      <div>
        <h3 className="font-semibold">{t('elder_mode')}</h3>
        <p className="text-sm text-slate-400">{t('simplified_ui')}</p>
      </div>
      <button
        onClick={() => onChange(!enabled)}
        className={`relative w-12 h-6 rounded-full transition-colors ${enabled ? 'bg-emerald-500' : 'bg-slate-700'}`}
      >
        <span
          className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${enabled ? 'translate-x-6' : 'translate-x-1'}`}
        />
      </button>
    </div>
  );
}