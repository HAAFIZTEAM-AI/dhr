import React, { createContext, useContext, useState, useEffect, useRef } from 'react';
import api from '../utils/api';
import { useAuth } from './AuthContext';
import { useAlarm } from './AlarmContext';

const FamilyContext = createContext();

export function FamilyProvider({ children }) {
  const { token } = useAuth();
  const { playAlarm } = useAlarm();
  const [familyGroup, setFamilyGroup] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [newAlert, setNewAlert] = useState(null);
  const lastAlertIdRef = useRef(null);

  const fetchFamily = async () => {
    if (!token) return;
    try {
      const res = await api.get('/family/mine');
      setFamilyGroup(res.data.group);
      if (res.data.group) {
        const alertsRes = await api.get('/family/alerts');
        const fetchedAlerts = alertsRes.data.alerts;
        setAlerts(fetchedAlerts);
        setUnreadCount(alertsRes.data.unread_count);

        if (fetchedAlerts.length > 0) {
          const latest = fetchedAlerts[0];
          if (lastAlertIdRef.current && latest.id !== lastAlertIdRef.current) {
            setNewAlert(latest);
            playAlarm('scam');
            setTimeout(() => setNewAlert(null), 5000);
          }
          lastAlertIdRef.current = latest.id;
        }
      } else {
        lastAlertIdRef.current = null;
      }
    } catch (err) {
      console.error('Family fetch error', err);
    }
  };

  useEffect(() => {
    fetchFamily();
    const interval = setInterval(fetchFamily, 5000);
    return () => clearInterval(interval);
  }, [token]);

  const createFamily = async (name) => {
    const res = await api.post('/family/create', { name });
    await fetchFamily();
    return res.data;
  };

  const joinFamily = async (inviteCode) => {
    const res = await api.post('/family/join', { invite_code: inviteCode });
    await fetchFamily();
    return res.data;
  };

  const sendAlert = async (message) => {
    if (!token) return { success: false, error: 'Not logged in' };
    try {
      const res = await api.post('/family/send-alert', { message });
      await fetchFamily();
      return { success: true, data: res.data };
    } catch (err) {
      console.error('Send alert error:', err);
      return { success: false, error: err.response?.data?.error || 'Failed to send alert' };
    }
  };

  return (
    <FamilyContext.Provider value={{
      familyGroup,
      alerts,
      unreadCount,
      newAlert,
      setNewAlert,
      fetchFamily,
      createFamily,
      joinFamily,
      sendAlert,
    }}>
      {children}
    </FamilyContext.Provider>
  );
}

export const useFamily = () => useContext(FamilyContext);