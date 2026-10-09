import React from 'react';
import { useLanguage } from '../../context/LanguageContext';

export default function LanguageSelector() {
  const { lang, setLang } = useLanguage();
  const languages = [
    { code: 'en', name: 'English', flag: '🇬🇧' },
    { code: 'ur', name: 'اردو', flag: '🇵🇰' },
    { code: 'roman', name: 'Roman Urdu', flag: '🇵🇰' },
    { code: 'sd', name: 'سنڌي', flag: '🇵🇰' },
    { code: 'pa', name: 'ਪੰਜਾਬੀ', flag: '🇵🇰' },
    { code: 'bal', name: 'بلوچی', flag: '🇵🇰' },
  ];

  return (
    <select
      value={lang}
      onChange={(e) => setLang(e.target.value)}
      className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500"
    >
      {languages.map(l => (
        <option key={l.code} value={l.code}>{l.flag} {l.name}</option>
      ))}
    </select>
  );
}