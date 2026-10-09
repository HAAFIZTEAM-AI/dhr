import React from 'react';
import TextScanner from './TextScanner';
import LinkScanner from './LinkScanner';
import ImageScanner from './ImageScanner';
import VoiceScanner from './VoiceScanner';
import MultimodalScanner from './MultimodalScanner';
import { useLanguage } from '../../context/LanguageContext';

export default function ScannerInterface({ mode, setMode }) {
  const { t } = useLanguage();
  const tabs = [
    { id: 'text', label: t('text_scan'), component: TextScanner },
    { id: 'url', label: t('link_scan'), component: LinkScanner },
    { id: 'image', label: t('image_scan'), component: ImageScanner },
    { id: 'voice', label: t('voice_scan'), component: VoiceScanner },
    { id: 'multimodal', label: t('multimodal_scan'), component: MultimodalScanner },
  ];

  const ActiveComponent = tabs.find(tab => tab.id === mode)?.component || TextScanner;

  return (
    <div>
      <div className="flex flex-wrap gap-2 mb-6">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setMode(tab.id)}
            className={`px-4 py-2 rounded-xl transition-all ${mode === tab.id ? 'bg-emerald-500 text-white' : 'bg-slate-800 text-slate-300 hover:bg-slate-700'}`}
          >
            {tab.label}
          </button>
        ))}
      </div>
      <ActiveComponent />
    </div>
  );
}