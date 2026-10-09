import React from 'react';

export default function SkeletonCard() {
  return (
    <div className="glass-card p-6 animate-pulse">
      <div className="h-4 bg-slate-700 rounded w-3/4 mb-4"></div>
      <div className="h-3 bg-slate-700 rounded w-full mb-2"></div>
      <div className="h-3 bg-slate-700 rounded w-5/6"></div>
    </div>
  );
}