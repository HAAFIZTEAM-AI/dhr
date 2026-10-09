import React from 'react';
import { Link } from 'react-router-dom';
import { Shield } from 'lucide-react';
import { useLanguage } from '../../context/LanguageContext';

export default function Footer() {
  const { t } = useLanguage();
  return (
    <footer className="hidden md:block border-t border-slate-800 py-8 px-4">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center">
        <div className="flex items-center space-x-2">
          <Shield className="w-5 h-5 text-emerald-400" />
          <span className="font-semibold">HAAFIZ v5.0</span>
        </div>
        <div className="flex space-x-4 text-sm text-slate-400">
          <Link to="/privacy" className="hover:text-white">{t('privacy_policy')}</Link>
          <Link to="/terms" className="hover:text-white">{t('terms')}</Link>
        </div>
      </div>
    </footer>
  );
}