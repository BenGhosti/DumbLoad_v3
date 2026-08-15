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

// Short-lived challenge storage: randomId -> { challenge, type, expiresAt }
const CHALLENGE_TTL = 5 * 60 * 1000; // 5 minutes
const challenges = new Map();

/**
 * Store a challenge and return a random ID for it
 * @param {string} challenge - Base64URL challenge
 * @param {string} type - 'registration' or 'authentication'
 * @returns {string} Random challenge ID
 */
function storeChallenge(challenge, type) {
  const id = crypto.randomBytes(16).toString('hex');
  challenges.set(id, {
    challenge,
    type,
    expiresAt: Date.now() + CHALLENGE_TTL
  });
  return id;
}

/**
 * Retrieve and consume a challenge by ID
 * @param {string} id - Challenge ID
 * @param {string} type - Expected type
 * @returns {string|null} Challenge string or null if invalid/expired
 */
function consumeChallenge(id, type) {
  const entry = challenges.get(id);
  if (!entry) return null;
  challenges.delete(id);
  if (entry.type !== type) return null;
  if (Date.now() > entry.expiresAt) return null;
  return entry.challenge;
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
async function generatePasskeyRegistrationOptions(passkeyName) {
  const existingKeys = await passkeyStore.getAllPasskeys();
  const excludeCredentials = existingKeys.map(key => ({
    id: key.id,
    transports: key.transports || []
  }));

  const options = await generateRegistrationOptions({
    rpName: config.rpName,
    rpID: config.rpId,
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

  const challengeId = storeChallenge(options.challenge, 'registration');
  return { challengeId, options };
}

/**
 * Verify a passkey registration response
 * @param {string} challengeId - Challenge ID from registration options
 * @param {Object} response - Registration response JSON from browser
 * @param {string} passkeyName - User-friendly name for the passkey
 * @returns {Promise<Object>} { verified, error?, name? }
 */
async function verifyPasskeyRegistration(challengeId, response, passkeyName) {
  const expectedChallenge = consumeChallenge(challengeId, 'registration');
  if (!expectedChallenge) {
    return { verified: false, error: 'Registration challenge expired or invalid. Please try again.' };
  }

  try {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: config.rpOrigin,
      expectedRPID: config.rpId,
      requireUserVerification: false
    });

    if (!verification.verified || !verification.registrationInfo) {
      return { verified: false, error: 'Registration verification failed' };
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
    return { verified: false, error: 'Registration verification failed' };
  }
}

/**
 * Generate authentication options for passkey login
 * @returns {Promise<Object>} { challengeId, options }
 */
async function generatePasskeyAuthOptions() {
  const options = await generateAuthenticationOptions({
    rpID: config.rpId,
    userVerification: 'preferred'
  });

  const challengeId = storeChallenge(options.challenge, 'authentication');
  return { challengeId, options };
}

/**
 * Verify a passkey authentication response and return the passkey name
 * @param {string} challengeId - Challenge ID from authentication options
 * @param {Object} response - Authentication response JSON from browser
 * @returns {Promise<Object>} { verified, error?, name? }
 */
async function verifyPasskeyAuthentication(challengeId, response) {
  const expectedChallenge = consumeChallenge(challengeId, 'authentication');
  if (!expectedChallenge) {
    return { verified: false, error: 'Authentication challenge expired or invalid. Please try again.' };
  }

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
      expectedOrigin: config.rpOrigin,
      expectedRPID: config.rpId,
      credential,
      requireUserVerification: false
    });

    if (!verification.verified || !verification.authenticationInfo) {
      return { verified: false, error: 'Authentication verification failed' };
    }

    // Update the stored counter to prevent replay attacks
    await passkeyStore.updatePasskey(credentialId, {
      counter: verification.authenticationInfo.newCounter,
      lastUsedAt: Date.now()
    });

    return { verified: true, name: storedKey.name };
  } catch (err) {
    logger.error(`Authentication verification error: ${err.message}`);
    return { verified: false, error: 'Authentication verification failed' };
  }
}

module.exports = {
  generatePasskeyRegistrationOptions,
  verifyPasskeyRegistration,
  generatePasskeyAuthOptions,
  verifyPasskeyAuthentication
};
