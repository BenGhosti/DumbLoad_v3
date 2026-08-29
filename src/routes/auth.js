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
const { createSession, destroySession, getSessionCookieOptions } = require('../utils/session');
const { getClientIp } = require('../utils/ipExtractor');
const { isAuthRequired } = require('../middleware/security');
const { isGuestFeatureEnabled, getGuestPinByPin, getPinStatus, updateGuestPin } = require('../utils/guestPins');

const SESSION_COOKIE_NAME = 'DUMBLOAD_SESSION';

/**
 * Verify PIN
 */
router.post('/verify-pin', async (req, res) => {
  const { pin } = req.body;
  const ip = getClientIp(req);
  
  try {
    // Reject PIN login when only passkey authentication is enabled
    if (config.authMode === 'passkey') {
      return res.status(403).json({
        success: false,
        error: 'PIN login is disabled. Use passkey authentication instead.'
      });
    }

    // If no PIN is set in config, always return success
    if (!config.pin) {
      res.clearCookie(SESSION_COOKIE_NAME, { path: '/' });
      res.clearCookie('DUMBLOAD_PIN', { path: '/' });
      return res.json({ success: true, error: null, path: '/' });
    }

    // Missing/empty PIN is a bad request
    if (!pin || typeof pin !== 'string' || pin.trim() === '') {
      logger.warn(`Empty PIN from IP: ${ip}`);
      return res.status(400).json({
        success: false,
        error: 'PIN is required'
      });
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
      return res.json({ success: true, error: null });
    }

    // Guest PIN fallback (shared PIN field): a valid guest PIN is confirmed
    // here; the UI then asks for the guest's name and completes the login
    // via /api/auth/guest-verify.
    if (isGuestFeatureEnabled()) {
      const guestRecord = await getGuestPinByPin(cleanedPin);
      if (guestRecord && getPinStatus(guestRecord) === 'active') {
        logger.info(`Guest PIN verified (${guestRecord.id}), awaiting name from IP: ${ip}`);
        return res.json({ success: true, requiresName: true, error: null });
      }
    }

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
  } catch (err) {
    logger.error(`PIN verification error: ${err.message}`);
    res.status(500).json({ success: false, error: 'Authentication failed' });
  }
});

/**
 * Guest PIN login.
 * Verifies a guest PIN and creates a guest session (upload-only rights).
 * Error messages are deliberately generic so attackers cannot distinguish
 * "expired/used-up" from "wrong PIN".
 */
router.post('/guest-verify', async (req, res) => {
  const ip = getClientIp(req);

  try {
    if (!isGuestFeatureEnabled()) {
      return res.status(403).json({
        success: false,
        error: 'Guest access is disabled'
      });
    }

    const { name, pin } = req.body || {};

    // Name validation (used for the guest folder name)
    if (!name || typeof name !== 'string' || name.trim() === '') {
      return res.status(400).json({ success: false, error: 'Name is required' });
    }
    if (name.trim().length > 50) {
      return res.status(400).json({ success: false, error: 'Name is too long' });
    }

    // PIN format: digits, same length as the master PIN
    if (!pin || typeof pin !== 'string' || !/^\d+$/.test(pin)) {
      return res.status(401).json({ success: false, error: 'PIN expired or invalid' });
    }
    if (config.pin && pin.length !== config.pin.length) {
      return res.status(401).json({ success: false, error: 'PIN expired or invalid' });
    }

    const record = await getGuestPinByPin(pin);
    if (!record || getPinStatus(record) !== 'active') {
      logger.warn(`Guest login failed (invalid/expired PIN) from IP: ${ip}`);
      return res.status(401).json({ success: false, error: 'PIN expired or invalid' });
    }

    // Create a guest session
    const cleanName = name.trim();
    await updateGuestPin(record.id, { name: cleanName }).catch(() => {});
    const sessionToken = createSession(ip, { role: 'guest', guestId: record.id });
    res.cookie(SESSION_COOKIE_NAME, sessionToken, getSessionCookieOptions(req));

    logger.info(`Guest "${cleanName}" logged in with PIN ${record.id} from IP: ${ip}`);
    res.json({ success: true, error: null });
  } catch (err) {
    logger.error(`Guest login error: ${err.message}`);
    res.status(500).json({ success: false, error: 'Guest login failed' });
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
 * Get full authentication status (mode, PIN length, passkey availability)
 * Used by the login page to render the correct UI
 */
router.get('/status', async (req, res) => {
  try {
    const passkeyStore = require('../services/passkeyStore');
    const passkeyCount = await passkeyStore.getPasskeyCount();

    res.json({
      required: isAuthRequired(),
      authMode: config.authMode,
      pinRequired: !!config.pin,
      pinLength: config.pin ? config.pin.length : 0,
      hasPasskeys: passkeyCount > 0,
      guestEnabled: isGuestFeatureEnabled()
    });
  } catch (err) {
    logger.error(`Auth status check error: ${err.message}`);
    res.status(500).json({ error: 'Failed to check auth status' });
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