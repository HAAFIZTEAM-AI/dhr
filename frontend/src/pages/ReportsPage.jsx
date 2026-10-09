import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { FileText, Plus } from 'lucide-react';
import api from '../utils/api';
import ReportCard from '../components/data/ReportCard';
import SkeletonCard from '../components/ui/SkeletonCard';
import { useLanguage } from '../context/LanguageContext';
import { useAuth } from '../context/AuthContext';

export default function ReportsPage() {
  const { t } = useLanguage();
  const { token } = useAuth();
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showNew, setShowNew] = useState(false);
  const [newContent, setNewContent] = useState('');

  const fetchReports = async () => {
    setLoading(true);
    try {
      const res = await api.get('/reports');
      setReports(res.data.reports);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  const handleCreate = async () => {
    if (!newContent.trim()) return;
    try {
      await api.post('/reports', { content: newContent, content_type: 'text', result: 'pending', confidence: 0, is_scam: false });
      setNewContent('');
      setShowNew(false);
      fetchReports();
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
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold flex items-center gap-2">
          <FileText className="w-8 h-8 text-cyan-400" /> {t('reports')}
        </h1>
        <button onClick={() => setShowNew(true)} className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" /> New
        </button>
      </div>
      {showNew && (
        <div className="glass-card p-4 mb-6">
          <textarea
            value={newContent}
            onChange={(e) => setNewContent(e.target.value)}
            placeholder="Report content..."
            className="input-field min-h-[100px]"
          />
          <div className="flex gap-2 mt-2">
            <button onClick={handleCreate} className="btn-primary">Save</button>
            <button onClick={() => setShowNew(false)} className="btn-primary bg-slate-700">Cancel</button>
          </div>
        </div>
      )}
      {loading ? (
        <div className="grid gap-4">
          {[...Array(4)].map((_, i) => <SkeletonCard key={i} />)}
        </div>
      ) : reports.length === 0 ? (
        <div className="glass-card p-12 text-center text-slate-400">No reports yet</div>
      ) : (
        <div className="grid gap-4">
          {reports.map(report => (
            <ReportCard key={report.id} report={report} onDelete={fetchReports} onUpdate={fetchReports} />
          ))}
        </div>
      )}
    </motion.div>
  );
}