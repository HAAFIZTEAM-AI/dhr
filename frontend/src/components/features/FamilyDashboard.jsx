import React, { useState } from 'react';
import { Users, Plus, Link as LinkIcon, AlertCircle, CheckCircle } from 'lucide-react';
import { useFamily } from '../../context/FamilyContext';
import { useLanguage } from '../../context/LanguageContext';
import { useAuth } from '../../context/AuthContext';
import FamilyAlertCard from './FamilyAlertCard';

export default function FamilyDashboard() {
  const { t } = useLanguage();
  const { user } = useAuth();
  const { familyGroup, createFamily, joinFamily, alerts } = useFamily();
  const [newGroupName, setNewGroupName] = useState('');
  const [inviteCode, setInviteCode] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [showJoin, setShowJoin] = useState(false);

  const handleCreate = async () => {
    if (!newGroupName.trim()) return;
    await createFamily(newGroupName);
    setNewGroupName('');
    setShowCreate(false);
  };

  const handleJoin = async () => {
    if (!inviteCode.trim()) return;
    await joinFamily(inviteCode);
    setInviteCode('');
    setShowJoin(false);
  };

  if (!familyGroup) {
    return (
      <div className="glass-card p-8 text-center">
        <Users className="w-12 h-12 text-slate-500 mx-auto mb-4" />
        <h3 className="text-xl font-semibold mb-4">{t('protect_family')}</h3>
        <p className="text-slate-400 mb-6">Create or join a family group to receive alerts when members scan threats.</p>
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <button onClick={() => setShowCreate(true)} className="btn-primary flex items-center gap-2">
            <Plus className="w-4 h-4" /> {t('create_family')}
          </button>
          <button onClick={() => setShowJoin(true)} className="btn-primary bg-slate-700 hover:bg-slate-600 flex items-center gap-2">
            <LinkIcon className="w-4 h-4" /> {t('join_family')}
          </button>
        </div>
        {showCreate && (
          <div className="mt-4">
            <input
              type="text"
              value={newGroupName}
              onChange={(e) => setNewGroupName(e.target.value)}
              placeholder="Family group name"
              className="input-field mb-2"
            />
            <button onClick={handleCreate} className="btn-primary w-full">Create</button>
          </div>
        )}
        {showJoin && (
          <div className="mt-4">
            <input
              type="text"
              value={inviteCode}
              onChange={(e) => setInviteCode(e.target.value)}
              placeholder={t('invite_code')}
              className="input-field mb-2"
            />
            <button onClick={handleJoin} className="btn-primary w-full">Join</button>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="glass-card p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-xl font-semibold flex items-center gap-2">
            <Users className="w-5 h-5 text-emerald-400" /> {familyGroup.name}
          </h3>
          <span className="text-sm text-slate-400">
            {t('invite_code')}: <span className="font-mono">{familyGroup.invite_code}</span>
          </span>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {familyGroup.members?.map(member => (
            <div key={member.id} className="flex items-center gap-2 bg-slate-800/50 rounded-xl p-3">
              <div className="w-8 h-8 rounded-full bg-emerald-500/20 flex items-center justify-center text-emerald-400 font-semibold">
                {member.username?.[0]?.toUpperCase() || 'U'}
              </div>
              <div>
                <p className="text-sm font-medium">{member.username}</p>
                <p className="text-xs text-slate-400">{member.role}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
      <div>
        <h4 className="text-lg font-semibold mb-4">{t('family_alerts')}</h4>
        <div className="space-y-3">
          {alerts.length === 0 ? (
            <div className="glass-card p-6 text-center text-slate-400">
              <CheckCircle className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
              No alerts yet
            </div>
          ) : (
            alerts.map(alert => <FamilyAlertCard key={alert.id} alert={alert} />)
          )}
        </div>
      </div>
    </div>
  );
}