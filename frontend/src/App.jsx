import React from 'react';
import { BrowserRouter as Router, Routes, Route, useLocation } from 'react-router-dom';
import { AnimatePresence } from 'framer-motion';
import { AuthProvider } from './context/AuthContext';
import { LanguageProvider } from './context/LanguageContext';
import { AlarmProvider } from './context/AlarmContext';
import { FamilyProvider } from './context/FamilyContext';
import { GamificationProvider } from './context/GamificationContext';

import Navbar from './components/layout/Navbar';
import Footer from './components/layout/Footer';
import BottomNav from './components/layout/BottomNav';
import ProtectedRoute from './components/layout/ProtectedRoute';
import FamilyAlertToast from './components/features/FamilyAlertToast';

import HomePage from './pages/HomePage';
import ScanPage from './pages/ScanPage';
import ThreatFeedPage from './pages/ThreatFeedPage';
import ReportsPage from './pages/ReportsPage';
import HistoryPage from './pages/HistoryPage';
import FamilyPage from './pages/FamilyPage';
import SettingsPage from './pages/SettingsPage';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';

function AnimatedRoutes() {
  const location = useLocation();
  return (
    <AnimatePresence mode="wait">
      <Routes location={location} key={location.pathname}>
        <Route path="/" element={<HomePage />} />
        <Route path="/scan" element={<ScanPage />} />
        <Route path="/threats" element={<ThreatFeedPage />} />
        <Route path="/reports" element={<ProtectedRoute><ReportsPage /></ProtectedRoute>} />
        <Route path="/history" element={<ProtectedRoute><HistoryPage /></ProtectedRoute>} />
        <Route path="/family" element={<ProtectedRoute><FamilyPage /></ProtectedRoute>} />
        <Route path="/settings" element={<ProtectedRoute><SettingsPage /></ProtectedRoute>} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
      </Routes>
    </AnimatePresence>
  );
}

function App() {
  return (
    <Router>
      <AuthProvider>
        <LanguageProvider>
          <AlarmProvider>
            <FamilyProvider>
              <GamificationProvider>
                <div className="min-h-screen bg-void text-slate-50 font-sans">
                  <Navbar />
                  <FamilyAlertToast /> {/* Add this line */}
                  <main className="pb-20 md:pb-0">
                    <AnimatedRoutes />
                  </main>
                  <Footer />
                  <BottomNav />
                </div>
              </GamificationProvider>
            </FamilyProvider>
          </AlarmProvider>
        </LanguageProvider>
      </AuthProvider>
    </Router>
  );
}

export default App;