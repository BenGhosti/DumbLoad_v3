/**
 * Passkey (WebAuthn) route handlers.
 * Provides authentication and admin-protected registration endpoints.
 */

const express = require('express');
const router = express.Router();
const { config } = require('../config');
const logger = require('../utils/logger');
const { createSession, SESSION_DURATION } = require('../utils/session');
const { getClientIp } = require('../utils/ipExtractor');
const { requireAuth } = require('../middleware/security');
const {
  generatePasskeyRegistrationOptions,
  verifyPasskeyRegistration,
  generatePasskeyAuthOptions,
  verifyPasskeyAuthentication
} = require('../services/passkey');
const passkeyStore = require('../services/passkeyStore');

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const SESSION_COOKIE_NAME = 'DUMBLOAD_SESSION';

/**
 * Generate authentication options for passkey login (public)
 */
router.post('/auth-options', async (req, res) => {
  try {
    const { challengeId, options } = await generatePasskeyAuthOptions();
    res.json({ challengeId, options });
  } catch (err) {
    logger.error(`Failed to generate auth options: ${err.message}`);
    res.status(500).json({ error: 'Failed to generate authentication options' });
  }
});

/**
 * Verify passkey authentication and create session (public)
 */
router.post('/auth-verify', async (req, res) => {
  const { challengeId, response } = req.body;
  const ip = getClientIp(req);

  if (!challengeId || !response) {
    return res.status(400).json({ error: 'Missing challengeId or response' });
  }

  try {
    const result = await verifyPasskeyAuthentication(challengeId, response);
    if (!result.verified) {
      logger.warn(`Failed passkey authentication from IP: ${ip}`);
      return res.status(401).json({ success: false, error: result.error || 'Authentication failed' });
    }

    // Create session token (8h expiry)
    const sessionToken = createSession(ip);
    res.cookie(SESSION_COOKIE_NAME, sessionToken, {
      httpOnly: true,
      secure: req.secure || (BASE_URL.startsWith('https') && NODE_ENV === 'production'),
      sameSite: 'strict',
      path: '/',
      maxAge: SESSION_DURATION
    });

    logger.info(`Successful passkey authentication from IP: ${ip} (${result.name})`);
    res.json({ success: true, error: null });
  } catch (err) {
    logger.error(`Passkey authentication error: ${err.message}`);
    res.status(500).json({ success: false, error: 'Authentication failed' });
  }
});

/**
 * Generate registration options for a new passkey (admin-protected)
 */
router.post('/register-options', requireAuth(), async (req, res) => {
  const { name } = req.body;
  if (!name || typeof name !== 'string' || name.trim() === '') {
    return res.status(400).json({ error: 'Passkey name is required' });
  }

  try {
    const { challengeId, options } = await generatePasskeyRegistrationOptions(name.trim());
    res.json({ challengeId, options });
  } catch (err) {
    logger.error(`Failed to generate registration options: ${err.message}`);
    res.status(500).json({ error: 'Failed to generate registration options' });
  }
});

/**
 * Verify and store a new passkey (admin-protected)
 */
router.post('/register-verify', requireAuth(), async (req, res) => {
  const { challengeId, response, name } = req.body;
  if (!challengeId || !response) {
    return res.status(400).json({ error: 'Missing challengeId or response' });
  }

  try {
    const result = await verifyPasskeyRegistration(challengeId, response, name);
    if (!result.verified) {
      return res.status(400).json({ error: result.error || 'Registration failed' });
    }

    logger.info(`Passkey registered: "${result.name}"`);
    res.json({ success: true, name: result.name });
  } catch (err) {
    logger.error(`Passkey registration error: ${err.message}`);
    res.status(500).json({ error: 'Registration failed' });
  }
});

/**
 * List registered passkeys (admin-protected)
 */
router.get('/list', requireAuth(), async (req, res) => {
  try {
    const keys = await passkeyStore.getAllPasskeys();
    // Don't expose sensitive data (publicKey, counter)
    const safeKeys = keys.map(key => ({
      id: key.id,
      name: key.name,
      createdAt: key.createdAt,
      lastUsedAt: key.lastUsedAt || null,
      deviceType: key.deviceType || null,
      backedUp: key.backedUp || false
    }));
    res.json({ passkeys: safeKeys });
  } catch (err) {
    logger.error(`Failed to list passkeys: ${err.message}`);
    res.status(500).json({ error: 'Failed to list passkeys' });
  }
});

/**
 * Remove a passkey (admin-protected)
 */
router.delete('/:credentialId', requireAuth(), async (req, res) => {
  const { credentialId } = req.params;
  try {
    const removed = await passkeyStore.removePasskey(credentialId);
    if (!removed) {
      return res.status(404).json({ error: 'Passkey not found' });
    }
    res.json({ success: true });
  } catch (err) {
    logger.error(`Failed to remove passkey: ${err.message}`);
    res.status(500).json({ error: 'Failed to remove passkey' });
  }
});

module.exports = router;
