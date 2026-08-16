/**
 * Passkey (WebAuthn) service.
 * Handles registration and authentication using @simplewebauthn/server.
 * Manages short-lived challenges for the WebAuthn ceremony.
 */

const crypto = require('crypto');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require('@simplewebauthn/server');
const { isoBase64URL } = require('@simplewebauthn/server/helpers');
const { config } = require('../config');
const logger = require('../utils/logger');
const passkeyStore = require('./passkeyStore');

// Short-lived challenge storage: randomId -> { challenge, type, rpId, rpOrigin, expiresAt }
const CHALLENGE_TTL = 5 * 60 * 1000; // 5 minutes
const challenges = new Map();

/**
 * Store a challenge (plus the RP context it was generated with) and return a random ID.
 * Storing the RP context ensures the verify step uses the EXACT same rpId/origin as
 * the options step, even if the request host differs slightly between the two calls.
 * @param {string} challenge - Base64URL challenge
 * @param {string} type - 'registration' or 'authentication'
 * @param {Object} context - { rpId, rpOrigin }
 * @returns {string} Random challenge ID
 */
function storeChallenge(challenge, type, context = {}) {
  const id = crypto.randomBytes(16).toString('hex');
  challenges.set(id, {
    challenge,
    type,
    rpId: context.rpId || config.rpId,
    rpOrigin: context.rpOrigin || config.rpOrigin,
    expiresAt: Date.now() + CHALLENGE_TTL
  });
  return id;
}

/**
 * Retrieve and consume a challenge entry by ID
 * @param {string} id - Challenge ID
 * @param {string} type - Expected type
 * @returns {Object|null} The challenge entry (with challenge, rpId, rpOrigin) or null
 */
function consumeChallenge(id, type) {
  const entry = challenges.get(id);
  if (!entry) return null;
  challenges.delete(id);
  if (entry.type !== type) return null;
  if (Date.now() > entry.expiresAt) return null;
  return entry;
}

/**
 * Decode the origin from a WebAuthn response's clientDataJSON (for diagnostics).
 * @param {Object} response - The credential response JSON
 * @returns {string} The client origin or "(unavailable)"
 */
function getClientOrigin(response) {
  try {
    const clientData = response && response.response && response.response.clientDataJSON;
    if (typeof clientData === 'string') {
      return JSON.parse(isoBase64URL.toUTF8String(clientData)).origin || '(unknown)';
    }
  } catch (err) {
    /* ignore - diagnostics only */
  }
  return '(unavailable)';
}

// Periodically clean up expired challenges
setInterval(() => {
  const now = Date.now();
  for (const [id, entry] of challenges.entries()) {
    if (now > entry.expiresAt) challenges.delete(id);
  }
}, 60 * 1000).unref();

// Stable user ID so all passkeys are registered for the same "user"
const STABLE_USER_ID = new TextEncoder().encode('dumbload-admin-user');

/**
 * Generate registration options for a new passkey
 * @param {string} passkeyName - User-friendly name for the passkey
 * @returns {Promise<Object>} { challengeId, options }
 */
async function generatePasskeyRegistrationOptions(passkeyName, context = {}) {
  const existingKeys = await passkeyStore.getAllPasskeys();
  const excludeCredentials = existingKeys.map(key => ({
    id: key.id,
    // Omit transports when empty: some browsers/authenticators reject empty arrays
    ...(key.transports && key.transports.length > 0 ? { transports: key.transports } : {})
  }));

  const options = await generateRegistrationOptions({
    rpName: config.rpName,
    rpID: context.rpId || config.rpId,
    userName: 'dumbload-admin',
    userID: STABLE_USER_ID,
    userDisplayName: passkeyName,
    attestationType: 'none',
    excludeCredentials,
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred'
    }
  });

  const challengeId = storeChallenge(options.challenge, 'registration', context);
  return { challengeId, options };
}

/**
 * Verify a passkey registration response
 * @param {string} challengeId - Challenge ID from registration options
 * @param {Object} response - Registration response JSON from browser
 * @param {string} passkeyName - User-friendly name for the passkey
 * @returns {Promise<Object>} { verified, error?, name? }
 */
async function verifyPasskeyRegistration(challengeId, response, passkeyName, context = {}) {
  const entry = consumeChallenge(challengeId, 'registration');
  if (!entry) {
    return { verified: false, error: 'Registration challenge expired or invalid. Please try again.' };
  }

  const expectedChallenge = entry.challenge;
  const rpId = context.rpId || entry.rpId || config.rpId;
  const rpOrigin = context.rpOrigin || entry.rpOrigin || config.rpOrigin;

  try {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: rpOrigin,
      expectedRPID: rpId,
      requireUserVerification: false
    });

    if (!verification.verified || !verification.registrationInfo) {
      const clientOrigin = getClientOrigin(response);
      logger.warn(
        `Passkey registration verification failed: expectedOrigin=${rpOrigin}, clientOrigin=${clientOrigin}, expectedRPID=${rpId}`
      );
      return {
        verified: false,
        error: `Registration verification failed (origin mismatch: server expected ${rpOrigin}, browser reported ${clientOrigin}). ` +
          'Make sure BASE_URL and the access URL match, and set TRUST_PROXY=true behind a reverse proxy.'
      };
    }

    const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;

    // Store the passkey
    await passkeyStore.addPasskey({
      id: credential.id,
      publicKey: isoBase64URL.fromBuffer(credential.publicKey),
      counter: credential.counter,
      transports: credential.transports || [],
      name: passkeyName || 'Unbenannter Schlüssel',
      createdAt: Date.now(),
      deviceType: credentialDeviceType,
      backedUp: credentialBackedUp
    });

    return { verified: true, name: passkeyName };
  } catch (err) {
    logger.error(`Registration verification error: ${err.message}`);
    return { verified: false, error: `Registration verification failed: ${err.message}` };
  }
}

/**
 * Generate authentication options for passkey login
 * @returns {Promise<Object>} { challengeId, options }
 */
async function generatePasskeyAuthOptions(context = {}) {
  // Include registered credentials so non-discoverable hardware keys (e.g. basic YubiKey U2F)
  // can also be used, in addition to discoverable passkeys.
  const existingKeys = await passkeyStore.getAllPasskeys();
  const allowCredentials = existingKeys.map(key => ({
    id: key.id,
    // Omit transports when empty: some browsers/authenticators reject empty arrays
    ...(key.transports && key.transports.length > 0 ? { transports: key.transports } : {})
  }));

  const options = await generateAuthenticationOptions({
    rpID: context.rpId || config.rpId,
    allowCredentials,
    userVerification: 'preferred'
  });

  const challengeId = storeChallenge(options.challenge, 'authentication', context);
  return { challengeId, options };
}

/**
 * Verify a passkey authentication response and return the passkey name
 * @param {string} challengeId - Challenge ID from authentication options
 * @param {Object} response - Authentication response JSON from browser
 * @returns {Promise<Object>} { verified, error?, name? }
 */
async function verifyPasskeyAuthentication(challengeId, response, context = {}) {
  const entry = consumeChallenge(challengeId, 'authentication');
  if (!entry) {
    return { verified: false, error: 'Authentication challenge expired or invalid. Please try again.' };
  }

  if (!response || typeof response !== 'object' || typeof response.id !== 'string' || !response.id) {
    return { verified: false, error: 'Invalid authentication response' };
  }

  const expectedChallenge = entry.challenge;
  const rpId = context.rpId || entry.rpId || config.rpId;
  const rpOrigin = context.rpOrigin || entry.rpOrigin || config.rpOrigin;

  const credentialId = response.id;
  const storedKey = await passkeyStore.getPasskey(credentialId);
  if (!storedKey) {
    return { verified: false, error: 'Passkey not recognized. Please register this key first.' };
  }

  try {
    const credential = {
      id: storedKey.id,
      publicKey: isoBase64URL.toBuffer(storedKey.publicKey),
      counter: storedKey.counter,
      transports: storedKey.transports || []
    };

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: rpOrigin,
      expectedRPID: rpId,
      credential,
      requireUserVerification: false
    });

    if (!verification.verified || !verification.authenticationInfo) {
      const clientOrigin = getClientOrigin(response);
      logger.warn(
        `Passkey authentication verification failed: expectedOrigin=${rpOrigin}, clientOrigin=${clientOrigin}, expectedRPID=${rpId}`
      );
      return {
        verified: false,
        error: `Authentication verification failed (origin mismatch: server expected ${rpOrigin}, browser reported ${clientOrigin}).`
      };
    }

    // Update the stored counter to prevent replay attacks
    await passkeyStore.updatePasskey(credentialId, {
      counter: verification.authenticationInfo.newCounter,
      lastUsedAt: Date.now()
    });

    return { verified: true, name: storedKey.name };
  } catch (err) {
    logger.error(`Authentication verification error: ${err.message}`);
    return { verified: false, error: `Authentication verification failed: ${err.message}` };
  }
}

module.exports = {
  generatePasskeyRegistrationOptions,
  verifyPasskeyRegistration,
  generatePasskeyAuthOptions,
  verifyPasskeyAuthentication
};
