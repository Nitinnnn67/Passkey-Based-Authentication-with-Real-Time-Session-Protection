import express from 'express';
import { getAuditLogs, getAllAuditLogs } from '../utils/auditLogger.js';

const router = express.Router();

/**
 * Get audit logs for current user
 */
router.get('/audit', (req, res) => {
  try {
    if (!req.session.userId) {
      // Return empty logs for non-authenticated users
      return res.json([]);
    }

    const logs = getAuditLogs(req.session.userId, 50);
    res.json(logs);
  } catch (error) {
    console.error('Audit logs error:', error);
    res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
});

/**
 * Get all audit logs (admin only - simplified for demo)
 */
router.get('/audit/all', (req, res) => {
  try {
    const logs = getAllAuditLogs(100);
    res.json(logs);
  } catch (error) {
    console.error('Audit logs error:', error);
    res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
});

export default router;
