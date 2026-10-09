import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle, X } from 'lucide-react';
import { useFamily } from '../../context/FamilyContext';

export default function FamilyAlertToast() {
  const { newAlert, setNewAlert } = useFamily();

  return (
    <AnimatePresence>
      {newAlert && (
        <motion.div
          initial={{ opacity: 0, y: -50 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -50 }}
          className="fixed top-20 right-4 z-50 bg-rose-500/90 backdrop-blur-md text-white p-4 rounded-xl shadow-lg max-w-sm"
        >
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 mt-0.5" />
            <div className="flex-1">
              <p className="font-semibold">Family Alert!</p>
              <p className="text-sm text-rose-100">{newAlert.message}</p>
            </div>
            <button onClick={() => setNewAlert(null)} className="text-white/80 hover:text-white">
              <X className="w-4 h-4" />
            </button>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}