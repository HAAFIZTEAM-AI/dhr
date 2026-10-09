import React from 'react';
import { AlertTriangle, MapPin, Clock } from 'lucide-react';

export default function ThreatCard({ threat }) {
  const severityColor = {
    low: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10',
    medium: 'text-amber-400 border-amber-500/30 bg-amber-500/10',
    high: 'text-orange-400 border-orange-500/30 bg-orange-500/10',
    critical: 'text-rose-400 border-rose-500/30 bg-rose-500/10'
  }[threat.severity] || 'text-slate-400 border-slate-500/30 bg-slate-500/10';

  return (
    <div className="glass-card p-4">
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-400 mt-0.5" />
          <div>
            <h3 className="font-semibold">{threat.title}</h3>
            <p className="text-sm text-slate-400 mt-1">{threat.description}</p>
          </div>
        </div>
        <span className={`text-xs px-2 py-1 rounded-full border ${severityColor}`}>
          {threat.severity}
        </span>
      </div>
      <div className="flex items-center gap-4 mt-3 text-xs text-slate-500">
        {threat.city && (
          <span className="flex items-center gap-1">
            <MapPin className="w-3 h-3" /> {threat.city}
          </span>
        )}
        <span className="flex items-center gap-1">
          <Clock className="w-3 h-3" /> {new Date(threat.created_at).toLocaleDateString()}
        </span>
        <span>{threat.type}</span>
      </div>
    </div>
  );
}