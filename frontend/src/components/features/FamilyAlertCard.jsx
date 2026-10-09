import React from 'react';
import { AlertTriangle, CheckCircle } from 'lucide-react';

export default function FamilyAlertCard({ alert }) {
  const isRead = alert.is_read;
  return (
    <div className={`glass-card p-4 flex items-start gap-3 ${!isRead ? 'border-emerald-500/30' : ''}`}>
      <AlertTriangle className="w-5 h-5 text-amber-400 mt-0.5" />
      <div className="flex-1">
        <p className="text-sm text-slate-200">{alert.message}</p>
        <p className="text-xs text-slate-500 mt-1">
          {new Date(alert.created_at).toLocaleString()}
        </p>
      </div>
      {!isRead && <span className="w-2 h-2 bg-emerald-400 rounded-full mt-2 animate-pulse" />}
    </div>
  );
}