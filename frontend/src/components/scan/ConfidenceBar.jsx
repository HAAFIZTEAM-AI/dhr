import React from 'react';
import { motion } from 'framer-motion';

export default function ConfidenceBar({ confidence }) {
  const getColor = () => {
    if (confidence >= 60) return 'bg-rose-500';
    if (confidence >= 30) return 'bg-amber-500';
    return 'bg-emerald-500';
  };

  return (
    <div className="w-full">
      <div className="flex justify-between text-sm mb-1">
        <span className="text-slate-400">Confidence</span>
        <span className="font-mono">{confidence}%</span>
      </div>
      <div className="h-3 bg-slate-800 rounded-full overflow-hidden">
        <motion.div
          className={`h-full ${getColor()}`}
          initial={{ width: 0 }}
          animate={{ width: `${confidence}%` }}
          transition={{ duration: 1.5, ease: 'easeOut' }}
        />
      </div>
    </div>
  );
}