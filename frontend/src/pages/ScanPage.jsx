import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useSearchParams } from 'react-router-dom';
import ScannerInterface from '../components/scan/ScannerInterface';
import { useLanguage } from '../context/LanguageContext';

export default function ScanPage() {
  const { t } = useLanguage();
  const [searchParams] = useSearchParams();
  const initialMode = searchParams.get('mode') || 'text';
  const [mode, setMode] = useState(initialMode);

  useEffect(() => {
    setMode(initialMode);
  }, [initialMode]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      transition={{ duration: 0.5 }}
      className="container mx-auto px-4 py-8"
    >
      <h1 className="text-3xl font-bold mb-6">{t('scanner')}</h1>
      <ScannerInterface mode={mode} setMode={setMode} />
    </motion.div>
  );
}