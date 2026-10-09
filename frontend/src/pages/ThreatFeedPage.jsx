import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { AlertTriangle, Plus, X } from 'lucide-react';
import api from '../utils/api';
import ThreatCard from '../components/data/ThreatCard';
import SkeletonCard from '../components/ui/SkeletonCard';
import { useLanguage } from '../context/LanguageContext';
import { useAuth } from '../context/AuthContext';

export default function ThreatFeedPage() {
  const { t } = useLanguage();
  const { token } = useAuth();
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [showForm, setShowForm] = useState(false);

  // Form state
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [type, setType] = useState('text');
  const [severity, setSeverity] = useState('medium');
  const [submitting, setSubmitting] = useState(false);

  const fetchThreats = async () => {
    setLoading(true);
    try {
      const res = await api.get(`/threats?page=${page}&limit=20`);
      setThreats(res.data.threats);
      setTotal(res.data.total);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats();
  }, [page]);

  const handleSubmit = async () => {
    if (!title.trim() || !description.trim()) {
      alert('Please fill title and description');
      return;
    }
    if (!token) {
      alert('Please login to report a threat');
      return;
    }
    setSubmitting(true);
    try {
      await api.post('/threats', {
        title,
        description,
        type,
        severity,
        city: '' // optional, can add city if desired
      });
      // Reset form and refresh
      setTitle('');
      setDescription('');
      setType('text');
      setSeverity('medium');
      setShowForm(false);
      fetchThreats();
    } catch (err) {
      console.error(err);
      alert('Failed to submit threat');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      transition={{ duration: 0.5 }}
      className="container mx-auto px-4 py-8"
    >
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <AlertTriangle className="w-8 h-8 text-amber-400" />
          <h1 className="text-3xl font-bold">{t('threats')}</h1>
        </div>
        <button
          onClick={() => setShowForm(true)}
          className="btn-primary flex items-center gap-2"
        >
          <Plus className="w-4 h-4" /> Report New Threat
        </button>
      </div>

      {/* Threat Reporting Form */}
      {showForm && (
        <div className="glass-card p-6 mb-6">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-xl font-semibold">Report a Scam/Threat</h2>
            <button onClick={() => setShowForm(false)} className="text-slate-400 hover:text-white">
              <X className="w-5 h-5" />
            </button>
          </div>
          <div className="space-y-4">
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Title (e.g., Fake JazzCash OTP Scam)"
              className="input-field"
              required
            />
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Description (how the scam works, what to look out for...)"
              className="input-field min-h-[120px]"
              required
            />
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <select
                value={type}
                onChange={(e) => setType(e.target.value)}
                className="input-field"
              >
                <option value="text">Text Scam</option>
                <option value="website">Website</option>
                <option value="voice">Voice/Phone</option>
                <option value="other">Other</option>
              </select>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
                className="input-field"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
            <button
              onClick={handleSubmit}
              disabled={submitting}
              className="btn-primary w-full"
            >
              {submitting ? 'Submitting...' : 'Submit Threat'}
            </button>
          </div>
        </div>
      )}

      {/* Threat List */}
      {loading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[...Array(6)].map((_, i) => <SkeletonCard key={i} />)}
        </div>
      ) : threats.length === 0 ? (
        <div className="glass-card p-12 text-center text-slate-400">
          {t('no_threats_found')}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {threats.map(threat => (
            <ThreatCard key={threat.id} threat={threat} />
          ))}
        </div>
      )}

      {/* Pagination */}
      {!loading && threats.length > 0 && (
        <div className="flex justify-center mt-6 gap-4">
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1}
            className="btn-primary bg-slate-700 disabled:opacity-50"
          >
            Previous
          </button>
          <span className="text-slate-400 py-2">Page {page}</span>
          <button
            onClick={() => setPage(p => p + 1)}
            disabled={page * 20 >= total}
            className="btn-primary"
          >
            Next
          </button>
        </div>
      )}
    </motion.div>
  );
}