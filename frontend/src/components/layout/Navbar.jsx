import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, Menu, X, LogOut } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { useLanguage } from '../../context/LanguageContext';
import LanguageSelector from '../ui/LanguageSelector';

export default function Navbar() {
  const { user, logout } = useAuth();
  const { t, dir } = useLanguage();
  const [isOpen, setIsOpen] = useState(false);
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  return (
    <header className="sticky top-0 z-50 backdrop-blur-md bg-slate-900/70 border-b border-slate-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          <Link to="/" className="flex items-center space-x-2">
            <Shield className="w-8 h-8 text-emerald-400" />
            <span className="font-bold text-xl gradient-text">HAAFIZ</span>
          </Link>

          {/* Desktop nav */}
          <nav className="hidden md:flex items-center space-x-6">
            <Link to="/scan" className="hover:text-emerald-400 transition-colors">{t('scan')}</Link>
            <Link to="/threats" className="hover:text-emerald-400 transition-colors">{t('threats')}</Link>
            {user && (
              <>
                <Link to="/history" className="hover:text-emerald-400 transition-colors">{t('history')}</Link>
                <Link to="/family" className="hover:text-emerald-400 transition-colors">{t('family')}</Link>
                <Link to="/reports" className="hover:text-emerald-400 transition-colors">{t('reports')}</Link>
              </>
            )}
          </nav>

          <div className="hidden md:flex items-center space-x-4">
            <LanguageSelector />
            {user ? (
              <button onClick={handleLogout} className="flex items-center space-x-1 text-slate-300 hover:text-white transition-colors">
                <LogOut className="w-4 h-4" />
                <span>{t('logout')}</span>
              </button>
            ) : (
              <Link to="/login" className="btn-primary">{t('login')}</Link>
            )}
          </div>

          {/* Mobile menu button */}
          <button className="md:hidden" onClick={() => setIsOpen(!isOpen)}>
            {isOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>
      </div>

      {/* Mobile menu */}
      {isOpen && (
        <div className="md:hidden glass border-t border-slate-800">
          <div className="px-4 py-3 space-y-2">
            <Link to="/scan" className="block py-2">{t('scan')}</Link>
            <Link to="/threats" className="block py-2">{t('threats')}</Link>
            {user && (
              <>
                <Link to="/history" className="block py-2">{t('history')}</Link>
                <Link to="/family" className="block py-2">{t('family')}</Link>
                <Link to="/reports" className="block py-2">{t('reports')}</Link>
              </>
            )}
            <div className="pt-2 border-t border-slate-800">
              <LanguageSelector />
              {user ? (
                <button onClick={handleLogout} className="w-full text-left py-2 text-rose-400">{t('logout')}</button>
              ) : (
                <Link to="/login" className="block py-2 text-emerald-400">{t('login')}</Link>
              )}
            </div>
          </div>
        </div>
      )}
    </header>
  );
}