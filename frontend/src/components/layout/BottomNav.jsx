import React from 'react';
import { NavLink } from 'react-router-dom';
import { Home, Shield, AlertTriangle, Users, Settings } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useLanguage } from '../../context/LanguageContext';

export default function BottomNav() {
  const { user } = useAuth();
  const { t } = useLanguage();
  
  return (
    <nav className="md:hidden fixed bottom-0 left-0 right-0 z-50 glass border-t border-slate-800">
      <div className="grid grid-cols-5 h-16">
        <NavLink to="/" className={({ isActive }) => `flex flex-col items-center justify-center ${isActive ? 'text-emerald-400' : 'text-slate-400'}`}>
          <Home className="w-5 h-5" />
          <span className="text-xs mt-1">{t('scan')}</span>
        </NavLink>
        <NavLink to="/scan" className={({ isActive }) => `flex flex-col items-center justify-center ${isActive ? 'text-emerald-400' : 'text-slate-400'}`}>
          <Shield className="w-5 h-5" />
          <span className="text-xs mt-1">{t('scan')}</span>
        </NavLink>
        <NavLink to="/threats" className={({ isActive }) => `flex flex-col items-center justify-center ${isActive ? 'text-emerald-400' : 'text-slate-400'}`}>
          <AlertTriangle className="w-5 h-5" />
          <span className="text-xs mt-1">{t('threats')}</span>
        </NavLink>
        {user && (
          <NavLink to="/family" className={({ isActive }) => `flex flex-col items-center justify-center ${isActive ? 'text-emerald-400' : 'text-slate-400'}`}>
            <Users className="w-5 h-5" />
            <span className="text-xs mt-1">{t('family')}</span>
          </NavLink>
        )}
        <NavLink to="/settings" className={({ isActive }) => `flex flex-col items-center justify-center ${isActive ? 'text-emerald-400' : 'text-slate-400'}`}>
          <Settings className="w-5 h-5" />
          <span className="text-xs mt-1">{t('settings')}</span>
        </NavLink>
      </div>
    </nav>
  );
}