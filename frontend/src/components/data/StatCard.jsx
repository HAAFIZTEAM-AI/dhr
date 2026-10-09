import React from 'react';
import AnimatedCounter from '../ui/AnimatedCounter';

export default function StatCard({ label, value, icon: Icon, color }) {
  return (
    <div className="glass-card p-6 flex items-center gap-4">
      <div className={`p-3 rounded-xl ${color}`}>
        {Icon && <Icon className="w-6 h-6" />}
      </div>
      <div>
        <div className="text-2xl font-bold">
          <AnimatedCounter value={value} />
        </div>
        <div className="text-sm text-slate-400">{label}</div>
      </div>
    </div>
  );
}