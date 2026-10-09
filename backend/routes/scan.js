import express from 'express';
import axios from 'axios';
import { authenticate } from '../middleware/auth.js';
import db from '../db.js';
import dotenv from 'dotenv';
dotenv.config();

const router = express.Router();
const AI_URL = process.env.AI_SERVICE_URL || 'http://localhost:5001';

router.post('/analyze', authenticate, async (req, res) => {
  try {
    const { text, url, image_base64, audio_base64, phone_number, language = 'en' } = req.body;
    const moduleResults = {};

    if (text) {
      const aiRes = await axios.post(`${AI_URL}/analyze/text`, { text, language });
      moduleResults.text = aiRes.data;
    }
    if (url) {
      const aiRes = await axios.post(`${AI_URL}/analyze/website`, { url });
      moduleResults.website = aiRes.data;
    }
    if (image_base64) {
      const aiRes = await axios.post(`${AI_URL}/analyze/image`, { image_base64 });
      moduleResults.image = aiRes.data;
    }
    if (audio_base64) {
      const aiRes = await axios.post(`${AI_URL}/analyze/voice`, { audio_base64, language });
      moduleResults.voice = aiRes.data;
    }
    if (phone_number) {
      const aiRes = await axios.post(`${AI_URL}/analyze/phone`, { phone_number });
      moduleResults.phone = aiRes.data;
    }

    const scores = Object.values(moduleResults).map(r => r.confidence || 0);
    const avgConfidence = scores.length ? Math.round(scores.reduce((a,b) => a+b, 0) / scores.length) : 0;
    const isScam = avgConfidence >= 60;
    const riskFactors = Object.values(moduleResults).flatMap(r => r.risk_factors || []);
    const explanation = isScam
      ? 'Multiple indicators suggest this is a scam.'
      : 'No significant scam indicators found.';

    const inputSummary = text || url || (image_base64 ? 'image' : '') || (audio_base64 ? 'audio' : '') || phone_number || 'unknown';
    const inputType = text ? 'text' : url ? 'url' : image_base64 ? 'image' : audio_base64 ? 'voice' : 'phone';

    db.run(
      `INSERT INTO history (user_id, input, input_type, result, confidence, is_scam, risk_factors, language)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [req.userId, inputSummary, inputType,
       isScam ? 'scam' : 'safe', avgConfidence, isScam, JSON.stringify(riskFactors), language],
      function (err) {
        if (err) console.error('History insert error:', err);
      }
    );

    // Family alert: if scam detected, add alert for family group (if any)
    if (isScam) {
      db.get(
        'SELECT group_id FROM family_members WHERE user_id = ?',
        [req.userId],
        (err, member) => {
          if (!err && member) {
            const message = `Scam detected by a family member: ${inputSummary} (Confidence: ${avgConfidence}%)`;
            db.run(
              'INSERT INTO family_alerts (group_id, triggered_by, message) VALUES (?, ?, ?)',
              [member.group_id, req.userId, message],
              (insErr) => {
                if (insErr) console.error('Family alert insert error:', insErr);
              }
            );
          }
        }
      );
    }

    res.json({
      is_scam: isScam,
      confidence: avgConfidence,
      risk_factors: riskFactors,
      explanation,
      recommended_action: isScam ? 'Do NOT click links. Do NOT share OTP. Block sender. Report to FIA.' : 'No action needed.',
      module_results: moduleResults
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Scan failed' });
  }
});

router.post('/quick-scan', async (req, res) => {
  try {
    const { text, url } = req.body;
    let confidence = 0;
    const riskFactors = [];
    if (text) {
      const keywords = ['otp', 'fia', 'state bank', 'nada', 'foran', 'urgent', 'prize', 'winner', 'block', 'suspend'];
      for (const kw of keywords) {
        if (text.toLowerCase().includes(kw)) {
          confidence += 10;
          riskFactors.push(kw);
        }
      }
      confidence = Math.min(confidence, 100);
    }
    res.json({ is_scam: confidence >= 60, confidence, risk_factors: riskFactors, source: 'heuristic' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

export default router;