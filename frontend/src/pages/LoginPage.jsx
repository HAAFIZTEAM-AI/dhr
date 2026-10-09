import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Link, useNavigate } from 'react-router-dom';
import { LogIn, Loader2 } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useLanguage } from '../context/LanguageContext';

export default function LoginPage() {
  const { t } = useLanguage();
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      await login(email, password);
      navigate('/');
    } catch (err) {
      setError(err.response?.data?.error || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      className="flex items-center justify-center min-h-[80vh]"
    >
      <form onSubmit={handleSubmit} className="glass-card p-8 w-full max-w-md">
        <div className="text-center mb-6">
          <LogIn className="w-12 h-12 text-emerald-400 mx-auto mb-4" />
          <h1 className="text-2xl font-bold">{t('login')}</h1>
        </div>
        {error && <div className="text-rose-400 text-sm mb-4 text-center">{error}</div>}
        <div className="space-y-4">
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Email"
            className="input-field"
            required
          />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Password"
            className="input-field"
            required
          />
          <button type="submit" disabled={loading} className="btn-primary w-full flex items-center justify-center gap-2">
            {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <LogIn className="w-5 h-5" />}
            {t('login')}
          </button>
        </div>
        <p className="text-center mt-4 text-sm text-slate-400">
          Don't have an account? <Link to="/register" className="text-emerald-400 hover:underline">{t('register')}</Link>
        </p>
      </form>
    </motion.div>
  );
}