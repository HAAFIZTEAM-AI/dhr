import React, { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Shield, Scan, MapPin, Users, Star, Bell } from 'lucide-react';
import { useLanguage } from '../context/LanguageContext';
import { useAuth } from '../context/AuthContext';
import { useGamification } from '../context/GamificationContext';
import AnimatedCounter from '../components/ui/AnimatedCounter';

export default function HomePage() {
  const { t } = useLanguage();
  const { user } = useAuth();
  const { points } = useGamification();
  const [stats, setStats] = useState({ total: 0, newToday: 0 });

  const containerVariants = {
    hidden: { opacity: 0 },
    show: { opacity: 1, transition: { staggerChildren: 0.1, delayChildren: 0.2 } }
  };
  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    show: { opacity: 1, y: 0, transition: { duration: 0.5, ease: 'easeOut' } }
  };

  useEffect(() => {
    // Fetch stats from API
    fetch('/api/threats/stats')
      .then(res => res.json())
      .then(data => setStats({ total: data.total, newToday: data.new_today }))
      .catch(() => {});
  }, []);

  return (
    <motion.div
      className="container mx-auto px-4 py-12"
      variants={containerVariants}
      initial="hidden"
      animate="show"
    >
      {/* Hero Section */}
      <motion.div variants={itemVariants} className="text-center mb-16 relative">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-96 h-96 bg-cyan-500/20 rounded-full blur-3xl -z-10 animate-float" />
        <motion.div
          initial={{ scale: 0.8, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ type: 'spring', stiffness: 100 }}
          className="inline-block mb-6"
        >
          <Shield className="w-20 h-20 text-emerald-400 mx-auto" />
        </motion.div>
        <h1 className="text-4xl md:text-6xl font-bold gradient-text mb-4">{t('app_name')}</h1>
        <p className="text-xl md:text-2xl text-slate-300 mb-8">{t('tagline')}</p>
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Link to="/scan" className="btn-primary text-lg px-8 py-3">
            <Scan className="inline-block mr-2" /> {t('scan_now')}
          </Link>
          <Link to="/threats" className="btn-primary bg-slate-700 hover:bg-slate-600 text-lg px-8 py-3">
            <MapPin className="inline-block mr-2" /> {t('threats')}
          </Link>
        </div>
      </motion.div>

      {/* Stats Section */}
      <motion.div variants={itemVariants} className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-16">
        <div className="glass-card p-6 text-center">
          <div className="text-4xl font-bold text-emerald-400">
            <AnimatedCounter value={stats.total} />
          </div>
          <div className="text-slate-400 mt-2">{t('total_threats')}</div>
        </div>
        <div className="glass-card p-6 text-center">
          <div className="text-4xl font-bold text-amber-400">
            <AnimatedCounter value={stats.newToday} />
          </div>
          <div className="text-slate-400 mt-2">{t('new_today')}</div>
        </div>
        <div className="glass-card p-6 text-center">
          <div className="text-4xl font-bold text-cyan-400">
            <AnimatedCounter value={points.total} />
          </div>
          <div className="text-slate-400 mt-2">{t('your_score')}</div>
        </div>
      </motion.div>

      {/* Feature Cards */}
      <motion.div variants={itemVariants} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Link to="/scan" className="glass-card p-6 hover:scale-105 transition-transform">
          <Scan className="w-10 h-10 text-emerald-400 mb-4" />
          <h3 className="text-xl font-semibold mb-2">{t('text_scan')}</h3>
          <p className="text-slate-400">Analyze suspicious messages</p>
        </Link>
        <Link to="/scan?mode=url" className="glass-card p-6 hover:scale-105 transition-transform">
          <MapPin className="w-10 h-10 text-cyan-400 mb-4" />
          <h3 className="text-xl font-semibold mb-2">{t('website_analyzer')}</h3>
          <p className="text-slate-400">Check fake websites</p>
        </Link>
        <Link to="/scan?mode=voice" className="glass-card p-6 hover:scale-105 transition-transform">
          <Bell className="w-10 h-10 text-amber-400 mb-4" />
          <h3 className="text-xl font-semibold mb-2">{t('voice_scan')}</h3>
          <p className="text-slate-400">Detect voice scams</p>
        </Link>
        <Link to="/family" className="glass-card p-6 hover:scale-105 transition-transform">
          <Users className="w-10 h-10 text-rose-400 mb-4" />
          <h3 className="text-xl font-semibold mb-2">{t('protect_family')}</h3>
          <p className="text-slate-400">Family alerts</p>
        </Link>
      </motion.div>
    </motion.div>
  );
}