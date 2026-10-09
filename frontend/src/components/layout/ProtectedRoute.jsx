import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';

export default function ProtectedRoute({ children }) {
  const { token, loading } = useAuth();
  if (loading) return <div className="flex justify-center items-center h-screen">Loading...</div>;
  if (!token) return <Navigate to="/login" replace />;
  return children;
}