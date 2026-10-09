import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { History, Trash2, Download } from 'lucide-react';
import api from '../utils/api';
import HistoryCard from '../components/data/HistoryCard';
import SkeletonCard from '../components/ui/SkeletonCard';
import { useLanguage } from '../context/LanguageContext';

export default function HistoryPage() {
  const { t } = useLanguage();
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const res = await api.get('/history', { params: { search } });
      setHistory(res.data.history);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const debounce = setTimeout(fetchHistory, 300);
    return () => clearTimeout(debounce);
  }, [search]);

  const handleDelete = async (id) => {
    try {
      await api.delete(`/history/${id}`);
      fetchHistory();
    } catch (err) {
      console.error(err);
    }
  };

  const handleClearAll = async () => {
    if (confirm('Clear all history?')) {
      await api.delete('/history');
      fetchHistory();
    }
  };

  const handleExport = async () => {
    try {
      const res = await api.get('/history/export', { responseType: 'blob' });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', 'haafiz_history.csv');
      document.body.appendChild(link);
      link.click();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      className="container mx-auto px-4 py-8"
    >
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-3xl font-bold flex items-center gap-2">
          <History className="w-8 h-8 text-emerald-400" /> {t('history')}
        </h1>
        <div className="flex gap-2">
          <button onClick={handleExport} className="btn-primary bg-slate-700 flex items-center gap-2">
            <Download className="w-4 h-4" /> Export
          </button>
          <button onClick={handleClearAll} className="btn-danger flex items-center gap-2">
            <Trash2 className="w-4 h-4" /> {t('clear_history')}
          </button>
        </div>
      </div>
      <input
        type="text"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        placeholder="Search history..."
        className="input-field mb-4"
      />
      {loading ? (
        <div className="grid gap-4">
          {[...Array(5)].map((_, i) => <SkeletonCard key={i} />)}
        </div>
      ) : history.length === 0 ? (
        <div className="glass-card p-12 text-center text-slate-400">No history yet</div>
      ) : (
        <div className="grid gap-4">
          {history.map(entry => (
            <HistoryCard key={entry.id} entry={entry} onDelete={handleDelete} />
          ))}
        </div>
      )}
    </motion.div>
  );
}