// Toast.jsx
import React from 'react';
import { motion } from 'framer-motion';
import { CheckCircle, XCircle, Info, AlertTriangle, X } from 'lucide-react';

export default function Toast({ type = 'info', message, onClose }) {
  const icons = {
    success: CheckCircle,
    error: XCircle,
    info: Info,
    warning: AlertTriangle,
  };
  const colors = {
    success: 'text-emerald-400',
    error: 'text-rose-400',
    info: 'text-cyan-400',
    warning: 'text-amber-400',
  };
  const Icon = icons[type];
  return (
    <motion.div
      initial={{ opacity: 0, x: 100 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 100 }}
      className={`glass-card p-4 flex items-center gap-3 ${colors[type]}`}
    >
      <Icon className="w-5 h-5" />
      <span className="flex-1 text-sm">{message}</span>
      <button onClick={onClose} className="text-slate-400 hover:text-white">
        <X className="w-4 h-4" />
      </button>
    </motion.div>
  );
}