import React from 'react';
import { Trash2, Shield, AlertTriangle } from 'lucide-react';

export default function HistoryCard({ entry, onDelete }) {
  return (
    <div className="glass-card p-4 flex items-center gap-3">
      {entry.is_scam ? (
        <AlertTriangle className="w-5 h-5 text-rose-400" />
      ) : (
        <Shield className="w-5 h-5 text-emerald-400" />
      )}
      <div className="flex-1 min-w-0">
        <p className="text-sm text-slate-300 truncate">{entry.input}</p>
        <p className="text-xs text-slate-500 mt-1">
          {new Date(entry.created_at).toLocaleString()} • Confidence: {entry.confidence}%
        </p>
      </div>
      <button onClick={() => onDelete(entry.id)} className="text-rose-400 hover:text-rose-300">
        <Trash2 className="w-4 h-4" />
      </button>
    </div>
  );
}