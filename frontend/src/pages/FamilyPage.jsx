import React from 'react';
import { motion } from 'framer-motion';
import { Users } from 'lucide-react';
import FamilyDashboard from '../components/features/FamilyDashboard';
import { useLanguage } from '../context/LanguageContext';

export default function FamilyPage() {
  const { t } = useLanguage();
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      className="container mx-auto px-4 py-8"
    >
      <h1 className="text-3xl font-bold mb-6 flex items-center gap-2">
        <Users className="w-8 h-8 text-emerald-400" /> {t('family')}
      </h1>
      <FamilyDashboard />
    </motion.div>
  );
}