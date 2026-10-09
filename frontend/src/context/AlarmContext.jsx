import React, { createContext, useContext, useState } from 'react';

const AlarmContext = createContext();

export function AlarmProvider({ children }) {
  const [enabled, setEnabled] = useState(true);

  const playAlarm = (severity) => {
    if (!enabled) return;
    const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const oscillator = audioCtx.createOscillator();
    const gainNode = audioCtx.createGain();
    oscillator.connect(gainNode);
    gainNode.connect(audioCtx.destination);
    oscillator.type = 'sine';
    
    if (severity === 'scam' || severity === 'critical') {
      // Urgent beeping
      oscillator.frequency.setValueAtTime(800, audioCtx.currentTime);
      oscillator.frequency.setValueAtTime(1200, audioCtx.currentTime + 0.1);
      oscillator.frequency.setValueAtTime(800, audioCtx.currentTime + 0.2);
      oscillator.frequency.setValueAtTime(1200, audioCtx.currentTime + 0.3);
      gainNode.gain.setValueAtTime(0.5, audioCtx.currentTime);
      oscillator.start(audioCtx.currentTime);
      oscillator.stop(audioCtx.currentTime + 0.4);
    } else if (severity === 'suspicious') {
      oscillator.frequency.setValueAtTime(600, audioCtx.currentTime);
      gainNode.gain.setValueAtTime(0.3, audioCtx.currentTime);
      oscillator.start(audioCtx.currentTime);
      oscillator.stop(audioCtx.currentTime + 0.2);
    } else {
      // Safe chime
      oscillator.frequency.setValueAtTime(440, audioCtx.currentTime);
      gainNode.gain.setValueAtTime(0.2, audioCtx.currentTime);
      oscillator.start(audioCtx.currentTime);
      oscillator.stop(audioCtx.currentTime + 0.1);
    }
  };

  return (
    <AlarmContext.Provider value={{ enabled, setEnabled, playAlarm }}>
      {children}
    </AlarmContext.Provider>
  );
}

export const useAlarm = () => useContext(AlarmContext);