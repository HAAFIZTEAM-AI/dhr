import React from 'react';

export default function PulseRing() {
  return (
    <div className="relative w-16 h-16">
      <div className="absolute inset-0 rounded-full bg-emerald-500/20 animate-ping"></div>
      <div className="absolute inset-0 rounded-full bg-emerald-500/40 animate-pulse"></div>
      <div className="relative w-full h-full rounded-full bg-emerald-500/80 flex items-center justify-center text-white font-bold">
        ...
      </div>
    </div>
  );
}