const express = require('express');
const router = express.Router();
const { config } = require('../config');
const logger = require('../utils/logger');
const { 
  validatePin, 
  safeCompare, 
  isLockedOut, 
  recordAttempt, 
  resetAttempts,
  MAX_ATTEMPTS,
  LOCKOUT_DURATION 
} = require('../utils/security');
const { createSession, destroySession, SESSION_DURATION } = require('../utils/session');
const { getClientIp } = require('../utils/ipExtractor');
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

const SESSION_COOKIE_NAME = 'DUMBLOAD_SESSION';

/**
 * Build secure cookie options for the session cookie
 * @param {object} req - Express request object
 * @returns {object} Cookie options
 */
function getSessionCookieOptions(req) {
  return {
    httpOnly: true,
    secure: req.secure || (BASE_URL.startsWith('https') && NODE_ENV === 'production'),
    sameSite: 'strict',
    path: '/',
    maxAge: SESSION_DURATION
  };
}
/**
 * Verify PIN
 */
router.post('/verify-pin', (req, res) => {
  const { pin } = req.body;
  const ip = getClientIp(req);
  
  try {
    // If no PIN is set in config, always return success
    if (!config.pin) {
      res.clearCookie(SESSION_COOKIE_NAME, { path: '/' });
      res.clearCookie('DUMBLOAD_PIN', { path: '/' });
      return res.json({ success: true, error: null, path: '/' });
    }

    // Validate PIN format
    const cleanedPin = validatePin(pin);
    if (!cleanedPin) {
      logger.warn(`Invalid PIN format from IP: ${ip}`);
      return res.status(401).json({ 
        success: false,
        error: 'Invalid PIN format. PIN must be 4-10 digits.' 
      });
    }

    // Check for lockout
    if (isLockedOut(ip)) {
      const attempts = recordAttempt(ip);
      const timeLeft = Math.ceil(
        (LOCKOUT_DURATION - (Date.now() - attempts.lastAttempt)) / 1000 / 60
      );
      
      logger.warn(`Login attempt from locked out IP: ${ip}`);
      return res.status(429).json({ 
        success: false,
        error: `Too many PIN verification attempts. Please try again in ${timeLeft} minutes.`
      });
    }

    // Verify the PIN using constant-time comparison
    if (safeCompare(cleanedPin, config.pin)) {
      // Reset attempts on successful login
      resetAttempts(ip);
      
      // Create a session token (8h expiry) instead of storing PIN directly
      const sessionToken = createSession(ip);
      res.cookie(SESSION_COOKIE_NAME, sessionToken, getSessionCookieOptions(req));

      logger.info(`Successful PIN verification from IP: ${ip}`);
      res.json({ success: true, error: null });
    } else {
      // Record failed attempt
      const attempts = recordAttempt(ip);
      const attemptsLeft = MAX_ATTEMPTS - attempts.count;
      
      logger.warn(`Failed PIN verification from IP: ${ip} (${attemptsLeft} attempts remaining)`);
      res.status(401).json({ 
        success: false, 
        error: attemptsLeft > 0 ? 
          `Invalid PIN. ${attemptsLeft} attempts remaining.` : 
          'Too many PIN verification attempts. Account locked for 15 minutes.'
      });
    }
  } catch (err) {
    logger.error(`PIN verification error: ${err.message}`);
    res.status(500).json({ success: false, error: 'Authentication failed' });
  }
});

/**
 * Check if PIN protection is enabled
 */
router.get('/pin-required', (req, res) => {
  try {
    res.json({ 
      required: !!config.pin,
      length: config.pin ? config.pin.length : 0
    });
  } catch (err) {
    logger.error(`PIN check error: ${err.message}`);
    res.status(500).json({ error: 'Failed to check PIN status' });
  }
});

/**
 * Logout (clear PIN cookie)
 */
router.post('/logout', (req, res) => {
  try {
    // Destroy the session token
    destroySession(req.cookies?.DUMBLOAD_SESSION);
    res.clearCookie(SESSION_COOKIE_NAME, { path: '/' });
    res.clearCookie('DUMBLOAD_PIN', { path: '/' });
    logger.info(`Logout successful for IP: ${getClientIp(req)}`);
    res.json({ success: true });
  } catch (err) {
    logger.error(`Logout error: ${err.message}`);
    res.status(500).json({ error: 'Logout failed' });
  }
});

module.exports = router; 