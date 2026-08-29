/**
 * Session management for authenticated users.
 * Uses cryptographically secure random tokens with 8-hour expiry.
 * Sessions are kept in-memory (lost on restart, acceptable for self-hosted use).
 */

const crypto = require('crypto');
const logger = require('./logger');
const { config } = require('../config');

const DEFAULT_SESSION_DURATION = 8 * 60 * 60 * 1000; // 8 hours

// In-memory TTL. For "instant" sessions (sessionTimeoutMs === 0) we still keep a
// generous in-memory lifetime - persistence is governed by the browser cookie.
const SESSION_TTL = config.sessionTimeoutMs > 0 ? config.sessionTimeoutMs : DEFAULT_SESSION_DURATION;

// Guest sessions get a shorter, independent lifetime
const GUEST_SESSION_TTL = config.guestSessionTimeoutMs > 0 ? config.guestSessionTimeoutMs : SESSION_TTL;

// Cookie maxAge in ms, or null for "instant" (a session cookie without maxAge,
// which the browser clears on close).
const SESSION_COOKIE_MAX_AGE = config.sessionTimeoutMs > 0 ? config.sessionTimeoutMs : null;

const sessions = new Map(); // token -> { createdAt, expiresAt, ip, role, guestId }

/**
 * Create a new session token for an authenticated user
 * @param {string} ip - Client IP address
 * @param {Object} [options] - { role: 'admin'|'guest', guestId }
 * @returns {string} Session token
 */
function createSession(ip, options = {}) {
  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  const role = options.role === 'guest' ? 'guest' : 'admin';
  const ttl = role === 'guest' ? GUEST_SESSION_TTL : SESSION_TTL;
  sessions.set(token, {
    createdAt: now,
    expiresAt: now + ttl,
    ip: ip || 'unknown',
    role,
    guestId: options.guestId || null,
  });
  logger.info(`Session created for IP ${ip || 'unknown'} (role: ${role})`);
  return token;
}

/**
 * Build the secure cookie options for the session cookie.
 * Respects SESSION_TIMEOUT ("instant" => session cookie without maxAge).
 * @param {object} req - Express request object
 * @returns {object} Cookie options
 */
function getSessionCookieOptions(req) {
  const baseUrl = process.env.BASE_URL || '';
  const isProduction = process.env.NODE_ENV === 'production';
  const options = {
    httpOnly: true,
    secure: req.secure || (baseUrl.startsWith('https') && isProduction),
    sameSite: 'strict',
    path: '/'
  };
  if (SESSION_COOKIE_MAX_AGE) {
    options.maxAge = SESSION_COOKIE_MAX_AGE;
  }
  return options;
}

/**
 * Check if a session token is valid and not expired
 * @param {string} token - Session token from cookie
 * @returns {Object|null} The session record, or null if invalid/expired
 */
function isValidSession(token) {
  if (!token || typeof token !== 'string') return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    sessions.delete(token);
    return null;
  }
  return session;
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
  getSessionCookieOptions,
  SESSION_DURATION: SESSION_TTL
};
