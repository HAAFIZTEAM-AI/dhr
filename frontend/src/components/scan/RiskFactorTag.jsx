import React from 'react';
import { AlertCircle } from 'lucide-react';

export default function RiskFactorTag({ factor }) {
  return (
    <span className="inline-flex items-center px-3 py-1 rounded-full bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-medium">
      <AlertCircle className="w-3 h-3 mr-1" />
      {factor}
    </span>
  );
}