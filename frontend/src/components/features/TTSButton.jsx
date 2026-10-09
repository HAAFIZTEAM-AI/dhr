import React from 'react';
import { Volume2 } from 'lucide-react';

export default function TTSButton({ text, lang }) {
  const speak = () => {
    if ('speechSynthesis' in window) {
      const utterance = new SpeechSynthesisUtterance(text);
      utterance.lang = lang === 'ur' ? 'ur-PK' : 'en-US';
      window.speechSynthesis.speak(utterance);
    }
  };

  return (
    <button onClick={speak} className="text-slate-400 hover:text-white transition-colors">
      <Volume2 className="w-5 h-5" />
    </button>
  );
}