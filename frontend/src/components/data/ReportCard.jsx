import React, { useState } from 'react';
import { Trash2, Edit2, Check, X } from 'lucide-react';
import api from '../../utils/api';

export default function ReportCard({ report, onDelete, onUpdate }) {
  const [isEditing, setIsEditing] = useState(false);
  const [content, setContent] = useState(report.content);

  const handleSave = async () => {
    try {
      await api.put(`/reports/${report.id}`, { content });
      onUpdate();
      setIsEditing(false);
    } catch (err) {
      console.error(err);
    }
  };

  const handleDelete = async () => {
    try {
      await api.delete(`/reports/${report.id}`);
      onDelete();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="glass-card p-4">
      {isEditing ? (
        <div className="space-y-2">
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            className="input-field min-h-[80px]"
          />
          <div className="flex gap-2">
            <button onClick={handleSave} className="btn-primary text-sm"><Check className="w-4 h-4" /></button>
            <button onClick={() => setIsEditing(false)} className="btn-primary bg-slate-700 text-sm"><X className="w-4 h-4" /></button>
          </div>
        </div>
      ) : (
        <div>
          <p className="text-sm text-slate-300">{report.content}</p>
          <div className="flex items-center justify-between mt-3">
            <span className={`text-xs px-2 py-1 rounded-full ${
              report.is_scam ? 'bg-rose-500/10 text-rose-400' : 'bg-emerald-500/10 text-emerald-400'
            }`}>
              {report.is_scam ? 'Scam' : 'Safe'} ({report.confidence}%)
            </span>
            <div className="flex gap-2">
              <button onClick={() => setIsEditing(true)} className="text-slate-400 hover:text-white"><Edit2 className="w-4 h-4" /></button>
              <button onClick={handleDelete} className="text-rose-400 hover:text-rose-300"><Trash2 className="w-4 h-4" /></button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}