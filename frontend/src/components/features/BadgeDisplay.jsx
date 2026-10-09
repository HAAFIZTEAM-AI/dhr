import React from 'react';
import { Award } from 'lucide-react';

export default function BadgeDisplay({ badges }) {
  if (!badges || badges.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-2">
      {badges.map((badge, idx) => (
        <div key={idx} className="flex items-center gap-1 bg-amber-500/10 border border-amber-500/30 rounded-full px-3 py-1 text-amber-400 text-sm">
          <Award className="w-4 h-4" />
          {badge}
        </div>
      ))}
    </div>
  );
}