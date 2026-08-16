/**
 * Passkey (WebAuthn) route handlers.
 * Provides authentication and admin-protected registration endpoints.
 */

const express = require('express');
const router = express.Router();
const { config } = require('../config');
const logger = require('../utils/logger');
const { createSession, getSessionCookieOptions } = require('../utils/session');
const { getClientIp } = require('../utils/ipExtractor');
const { requireAuth } = require('../middleware/security');
const {
  generatePasskeyRegistrationOptions,
  verifyPasskeyRegistration,
  generatePasskeyAuthOptions,
  verifyPasskeyAuthentication
} = require('../services/passkey');
const passkeyStore = require('../services/passkeyStore');

const SESSION_COOKIE_NAME = 'DUMBLOAD_SESSION';

/**
 * Derive the WebAuthn Relying Party context from the incoming request.
 * Using the request's own host fixes "rp.id cannot be used with the current
 * origin" errors that happen when BASE_URL differs from how the user actually
 * accesses the app (different hostname/IP/port). DUMBLOAD_RP_ID still acts as
 * an explicit override.
 * @param {object} req - Express request object
 * @returns {{rpId: string, rpOrigin: string}}
 */
function getRpContext(req) {
  const explicitRpId = (process.env.DUMBLOAD_RP_ID || '').trim();
  const rpId = explicitRpId || req.hostname || config.rpId || 'localhost';

  // Determine the public-facing origin protocol. The Node.js server only ever
  // speaks plain HTTP, so detect HTTPS from (in order):
  //   1. req.protocol (correct when TRUST_PROXY=true is set)
  //   2. the X-Forwarded-Proto header set by a reverse proxy (e.g. Nginx PM)
  //   3. BASE_URL starting with https://
  let protocol = req.protocol;
  if (protocol === 'http') {
    const forwardedProto = ((req.headers['x-forwarded-proto'] || '').toString().split(',')[0] || '').trim();
    if (forwardedProto === 'https' || /^https:\/\//i.test(process.env.BASE_URL || '')) {
      protocol = 'https';
    }
  }

  const rpOrigin = `${protocol}://${req.get('host')}`;
  return { rpId, rpOrigin };
}

/**
 * Middleware that blocks ALL passkey management endpoints when the admin
 * interface is disabled (DUMBLOAD_ADMIN_PATH not set in .env).
 * Login endpoints (auth-options/auth-verify) are NOT affected.
 */
function requireAdminEnabled(req, res, next) {
  if (!config.adminEnabled) {
    return res.status(404).json({ error: 'Not found' });
  }
  return next();
}

/**
 * Generate authentication options for passkey login (public)
 */
router.post('/auth-options', async (req, res) => {
  // Reject passkey login when only PIN authentication is enabled
  if (config.authMode === 'pin') {
    return res.status(403).json({ error: 'Passkey login is disabled. Use PIN authentication instead.' });
  }

  try {
    const { challengeId, options } = await generatePasskeyAuthOptions(getRpContext(req));
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
  // Reject passkey login when only PIN authentication is enabled
  if (config.authMode === 'pin') {
    return res.status(403).json({ success: false, error: 'Passkey login is disabled. Use PIN authentication instead.' });
  }

  const { challengeId, response } = req.body;
  const ip = getClientIp(req);

  if (!challengeId || !response) {
    return res.status(400).json({ error: 'Missing challengeId or response' });
  }

  try {
    const result = await verifyPasskeyAuthentication(challengeId, response, getRpContext(req));
    if (!result.verified) {
      logger.warn(`Failed passkey authentication from IP: ${ip}`);
      return res.status(401).json({ success: false, error: result.error || 'Authentication failed' });
    }

    // Create session token
    const sessionToken = createSession(ip);
    res.cookie(SESSION_COOKIE_NAME, sessionToken, getSessionCookieOptions(req));

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
router.post('/register-options', requireAdminEnabled, requireAuth(), async (req, res) => {
  const { name } = req.body;
  if (!name || typeof name !== 'string' || name.trim() === '') {
    return res.status(400).json({ error: 'Passkey name is required' });
  }

  try {
    const { challengeId, options } = await generatePasskeyRegistrationOptions(name.trim(), getRpContext(req));
    res.json({ challengeId, options });
  } catch (err) {
    logger.error(`Failed to generate registration options: ${err.message}`);
    res.status(500).json({ error: 'Failed to generate registration options', details: err.message });
  }
});

/**
 * Verify and store a new passkey (admin-protected)
 */
router.post('/register-verify', requireAdminEnabled, requireAuth(), async (req, res) => {
  const { challengeId, response, name } = req.body;
  if (!challengeId || !response) {
    return res.status(400).json({ error: 'Missing challengeId or response' });
  }

  // Re-validate the passkey name (trimmed, bounded length)
  const safeName = (typeof name === 'string' && name.trim()) ? name.trim().slice(0, 50) : 'Unbenannter Schlüssel';

  try {
    const result = await verifyPasskeyRegistration(challengeId, response, safeName, getRpContext(req));
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
router.get('/list', requireAdminEnabled, requireAuth(), async (req, res) => {
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
router.delete('/:credentialId', requireAdminEnabled, requireAuth(), async (req, res) => {
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
