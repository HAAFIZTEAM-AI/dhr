import React, { useRef, useState, useEffect } from 'react';
import { Mic, Square, Trash2 } from 'lucide-react';
import { useLanguage } from '../../context/LanguageContext';

export default function VoiceRecorder({ onRecordingComplete }) {
  const { t } = useLanguage();
  const [isRecording, setIsRecording] = useState(false);
  const [audioURL, setAudioURL] = useState(null);
  const [recordingTime, setRecordingTime] = useState(0);
  const mediaRecorderRef = useRef(null);
  const audioChunksRef = useRef([]);
  const timerRef = useRef(null);

  const startRecording = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      mediaRecorderRef.current = new MediaRecorder(stream);
      audioChunksRef.current = [];

      mediaRecorderRef.current.ondataavailable = (event) => {
        audioChunksRef.current.push(event.data);
      };

      mediaRecorderRef.current.onstop = () => {
        const audioBlob = new Blob(audioChunksRef.current, { type: 'audio/wav' });
        const url = URL.createObjectURL(audioBlob);
        setAudioURL(url);
        onRecordingComplete(audioBlob);
        stream.getTracks().forEach(track => track.stop());
      };

      mediaRecorderRef.current.start();
      setIsRecording(true);
      timerRef.current = setInterval(() => {
        setRecordingTime(prev => prev + 1);
      }, 1000);
    } catch (err) {
      console.error('Error accessing microphone:', err);
      alert('Microphone access denied. Please enable it in browser settings.');
    }
  };

  const stopRecording = () => {
    if (mediaRecorderRef.current && isRecording) {
      mediaRecorderRef.current.stop();
      setIsRecording(false);
      clearInterval(timerRef.current);
      setRecordingTime(0);
    }
  };

  const deleteRecording = () => {
    setAudioURL(null);
    onRecordingComplete(null);
  };

  useEffect(() => {
    return () => clearInterval(timerRef.current);
  }, []);

  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-4">
        <button
          onClick={isRecording ? stopRecording : startRecording}
          className={`px-6 py-3 rounded-xl font-medium flex items-center gap-2 transition-all ${
            isRecording ? 'bg-rose-500 hover:bg-rose-600' : 'bg-emerald-500 hover:bg-emerald-600'
          }`}
        >
          {isRecording ? (
            <>
              <Square className="w-5 h-5" />
              Stop ({formatTime(recordingTime)})
            </>
          ) : (
            <>
              <Mic className="w-5 h-5" />
              {t('record_audio')}
            </>
          )}
        </button>
        {audioURL && (
          <>
            <audio controls src={audioURL} className="max-w-xs" />
            <button onClick={deleteRecording} className="text-rose-400 hover:text-rose-300">
              <Trash2 className="w-5 h-5" />
            </button>
          </>
        )}
      </div>
      {isRecording && (
        <div className="text-center text-sm text-rose-400 animate-pulse">
          Recording... {formatTime(recordingTime)}
        </div>
      )}
    </div>
  );
}