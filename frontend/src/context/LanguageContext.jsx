import React, { createContext, useContext, useState, useEffect } from 'react';
import { translations } from '../i18n/translations';

const LanguageContext = createContext();

export function LanguageProvider({ children }) {
  const [lang, setLang] = useState(localStorage.getItem('haafiz_lang') || 'en');
  const [dir, setDir] = useState('ltr');

  useEffect(() => {
    const rtlLangs = ['ur', 'sd', 'bal'];
    setDir(rtlLangs.includes(lang) ? 'rtl' : 'ltr');
    document.documentElement.dir = rtlLangs.includes(lang) ? 'rtl' : 'ltr';
    localStorage.setItem('haafiz_lang', lang);
  }, [lang]);

  const t = (key) => {
    const langObj = translations[lang] || translations.en;
    return langObj[key] || translations.en[key] || key;
  };

  return (
    <LanguageContext.Provider value={{ lang, setLang, dir, t }}>
      {children}
    </LanguageContext.Provider>
  );
}

export const useLanguage = () => useContext(LanguageContext);