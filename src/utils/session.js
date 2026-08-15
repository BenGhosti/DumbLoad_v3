/**
 * Session management for authenticated users.
 * Uses cryptographically secure random tokens with 8-hour expiry.
 * Sessions are kept in-memory (lost on restart, acceptable for self-hosted use).
 */

const crypto = require('crypto');
const logger = require('./logger');

const SESSION_DURATION = 8 * 60 * 60 * 1000; // 8 hours

const sessions = new Map(); // token -> { createdAt, expiresAt, ip }

/**
 * Create a new session token for an authenticated user
 * @param {string} ip - Client IP address
 * @returns {string} Session token
 */
function createSession(ip) {
  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  sessions.set(token, {
    createdAt: now,
    expiresAt: now + SESSION_DURATION,
    ip: ip || 'unknown'
  });
  logger.info(`Session created for IP ${ip || 'unknown'}`);
  return token;
}

/**
 * Check if a session token is valid and not expired
 * @param {string} token - Session token from cookie
 * @returns {boolean} True if session is valid
 */
function isValidSession(token) {
  if (!token || typeof token !== 'string') return false;
  const session = sessions.get(token);
  if (!session) return false;
  if (Date.now() > session.expiresAt) {
    sessions.delete(token);
    return false;
  }
  return true;
}

/**
 * Destroy a session token (logout)
 * @param {string} token - Session token to destroy
 */
function destroySession(token) {
  if (!token) return;
  const existed = sessions.delete(token);
  if (existed) {
    logger.info('Session destroyed (logout)');
  }
}

/**
 * Get the number of active sessions (for debugging/monitoring)
 * @returns {number} Active session count
 */
function getActiveSessionCount() {
  return sessions.size;
}

// Periodically clean up expired sessions (hourly)
const cleanupInterval = setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  for (const [token, session] of sessions.entries()) {
    if (now > session.expiresAt) {
      sessions.delete(token);
      cleaned++;
    }
  }
  if (cleaned > 0) {
    logger.info(`Cleaned up ${cleaned} expired sessions`);
  }
}, 60 * 60 * 1000); // Every hour

cleanupInterval.unref(); // Don't keep the process alive

module.exports = {
  createSession,
  isValidSession,
  destroySession,
  getActiveSessionCount,
  SESSION_DURATION
};
