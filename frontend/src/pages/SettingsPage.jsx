import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Settings, Bell, Languages, Users, Shield } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useLanguage } from '../context/LanguageContext';
import { useAlarm } from '../context/AlarmContext';
import ElderModeToggle from '../components/features/ElderModeToggle';
import LanguageSelector from '../components/ui/LanguageSelector';
import { useGamification } from '../context/GamificationContext';
import BadgeDisplay from '../components/features/BadgeDisplay';

export default function SettingsPage() {
  const { user, logout } = useAuth();
  const { t, lang, setLang } = useLanguage();
  const { enabled, setEnabled } = useAlarm();
  const { points } = useGamification();
  const [elderMode, setElderMode] = useState(localStorage.getItem('elder_mode') === 'true');

  const toggleElderMode = (val) => {
    setElderMode(val);
    localStorage.setItem('elder_mode', val.toString());
    // Optionally dispatch event or context
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      className="container mx-auto px-4 py-8 max-w-3xl"
    >
      <h1 className="text-3xl font-bold mb-6 flex items-center gap-2">
        <Settings className="w-8 h-8 text-slate-400" /> {t('settings')}
      </h1>

      <div className="space-y-6">
        <div className="glass-card p-6">
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <Languages className="w-5 h-5 text-cyan-400" /> {t('language')}
          </h2>
          <LanguageSelector />
        </div>

        <div className="glass-card p-6">
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <Bell className="w-5 h-5 text-amber-400" /> {t('notifications')}
          </h2>
          <div className="flex items-center justify-between">
            <span>{t('alarm_on')}</span>
            <button
              onClick={() => setEnabled(!enabled)}
              className={`relative w-12 h-6 rounded-full transition-colors ${enabled ? 'bg-emerald-500' : 'bg-slate-700'}`}
            >
              <span
                className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-transform ${enabled ? 'translate-x-6' : 'translate-x-1'}`}
              />
            </button>
          </div>
        </div>

        <ElderModeToggle enabled={elderMode} onChange={toggleElderMode} />

        {user && (
          <div className="glass-card p-6">
            <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
              <Shield className="w-5 h-5 text-emerald-400" /> {t('your_score')}
            </h2>
            <div className="text-3xl font-bold text-emerald-400">{points.total}</div>
            <p className="text-sm text-slate-400">Level {points.level} • Streak {points.streak} days</p>
            {points.badges.length > 0 && <BadgeDisplay badges={points.badges} />}
          </div>
        )}

        {user && (
          <button onClick={logout} className="btn-danger w-full">
            {t('logout')}
          </button>
        )}
      </div>
    </motion.div>
  );
}