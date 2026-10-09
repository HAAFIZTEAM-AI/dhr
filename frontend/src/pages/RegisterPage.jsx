import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Link, useNavigate } from 'react-router-dom';
import { UserPlus, Loader2 } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useLanguage } from '../context/LanguageContext';

export default function RegisterPage() {
  const { t } = useLanguage();
  const { register } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      await register(username, email, password);
      navigate('/');
    } catch (err) {
      setError(err.response?.data?.error || 'Registration failed');
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
          <UserPlus className="w-12 h-12 text-emerald-400 mx-auto mb-4" />
          <h1 className="text-2xl font-bold">{t('register')}</h1>
        </div>
        {error && <div className="text-rose-400 text-sm mb-4 text-center">{error}</div>}
        <div className="space-y-4">
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Username"
            className="input-field"
            required
          />
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
            minLength={6}
          />
          <button type="submit" disabled={loading} className="btn-primary w-full flex items-center justify-center gap-2">
            {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <UserPlus className="w-5 h-5" />}
            {t('register')}
          </button>
        </div>
        <p className="text-center mt-4 text-sm text-slate-400">
          Already have an account? <Link to="/login" className="text-emerald-400 hover:underline">{t('login')}</Link>
        </p>
      </form>
    </motion.div>
  );
}