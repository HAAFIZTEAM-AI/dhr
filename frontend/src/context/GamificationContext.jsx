import React, { createContext, useContext, useState, useEffect } from 'react';
import api from '../utils/api';
import { useAuth } from './AuthContext';

const GamificationContext = createContext();

export function GamificationProvider({ children }) {
  const { token } = useAuth();
  const [points, setPoints] = useState({ total: 0, level: 1, badges: [], streak: 0 });

  const fetchPoints = async () => {
    if (!token) return;
    try {
      const res = await api.get('/gamification/points');
      setPoints({
        total: res.data.total_points,
        level: res.data.current_level,
        badges: res.data.badges,
        streak: res.data.login_streak
      });
    } catch (err) {
      console.error('Points fetch error', err);
    }
  };

  useEffect(() => {
    fetchPoints();
  }, [token]);

  const awardPoints = async (amount, badge, reason) => {
    try {
      const res = await api.post('/gamification/award', { points: amount, badge, reason });
      await fetchPoints();
      return res.data;
    } catch (err) {
      console.error('Award error', err);
    }
  };

  const recordStreak = async () => {
    try {
      await api.post('/gamification/streak');
      await fetchPoints();
    } catch (err) {
      console.error('Streak error', err);
    }
  };

  return (
    <GamificationContext.Provider value={{ points, fetchPoints, awardPoints, recordStreak }}>
      {children}
    </GamificationContext.Provider>
  );
}

export const useGamification = () => useContext(GamificationContext);