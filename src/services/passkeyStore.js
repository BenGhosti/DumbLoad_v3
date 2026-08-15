/**
 * Passkey credential storage.
 * Persists WebAuthn credentials to a JSON file in the upload directory.
 * Each passkey has a user-friendly name (e.g. "Büro-Key", "Handy").
 */

const fs = require('fs');
const path = require('path');
const { config } = require('../config');
const logger = require('../utils/logger');

let passkeys = null; // In-memory cache: array of passkey records

/**
 * Load passkeys from disk (lazy, cached)
 * @returns {Promise<Array>} Array of passkey records
 */
async function loadPasskeys() {
  if (passkeys !== null) return passkeys;
  try {
    const data = await fs.promises.readFile(config.passkeyFilePath, 'utf8');
    passkeys = JSON.parse(data);
    if (!Array.isArray(passkeys)) passkeys = [];
    logger.info(`Loaded ${passkeys.length} passkey(s) from storage`);
  } catch (err) {
    if (err.code === 'ENOENT') {
      passkeys = [];
      logger.info('No passkey storage file found, starting with empty list');
    } else {
      logger.error(`Failed to load passkeys: ${err.message}`);
      passkeys = [];
    }
  }
  return passkeys;
}

/**
 * Save passkeys to disk (atomic write)
 * @param {Array} keys - Array of passkey records to persist
 */
async function savePasskeys(keys) {
  passkeys = keys;
  const tempPath = `${config.passkeyFilePath}.${Date.now()}.tmp`;
  try {
    await fs.promises.mkdir(path.dirname(config.passkeyFilePath), { recursive: true });
    await fs.promises.writeFile(tempPath, JSON.stringify(keys, null, 2));
    await fs.promises.rename(tempPath, config.passkeyFilePath);
  } catch (err) {
    logger.error(`Failed to save passkeys: ${err.message}`);
    try { await fs.promises.unlink(tempPath); } catch { /* ignore */ }
    throw err;
  }
}

/**
 * Get all passkeys
 * @returns {Promise<Array>} Array of passkey records
 */
async function getAllPasskeys() {
  return await loadPasskeys();
}

/**
 * Get a single passkey by credential ID
 * @param {string} credentialId - Base64URL credential ID
 * @returns {Promise<Object|null>} Passkey record or null
 */
async function getPasskey(credentialId) {
  const keys = await loadPasskeys();
  return keys.find(k => k.id === credentialId) || null;
}

/**
 * Add a new passkey
 * @param {Object} record - Passkey record to add
 */
async function addPasskey(record) {
  const keys = await loadPasskeys();
  keys.push(record);
  await savePasskeys(keys);
  logger.info(`Added passkey "${record.name || record.id}"`);
}

/**
 * Update an existing passkey (e.g. counter after authentication)
 * @param {string} credentialId - Base64URL credential ID
 * @param {Object} updates - Fields to update
 */
async function updatePasskey(credentialId, updates) {
  const keys = await loadPasskeys();
  const index = keys.findIndex(k => k.id === credentialId);
  if (index === -1) return false;
  keys[index] = { ...keys[index], ...updates };
  await savePasskeys(keys);
  return true;
}

/**
 * Remove a passkey by credential ID
 * @param {string} credentialId - Base64URL credential ID
 * @returns {Promise<boolean>} True if removed
 */
async function removePasskey(credentialId) {
  const keys = await loadPasskeys();
  const index = keys.findIndex(k => k.id === credentialId);
  if (index === -1) return false;
  const removed = keys.splice(index, 1)[0];
  await savePasskeys(keys);
  logger.info(`Removed passkey "${removed.name || removed.id}"`);
  return true;
}

/**
 * Get the count of registered passkeys
 * @returns {Promise<number>} Number of passkeys
 */
async function getPasskeyCount() {
  const keys = await loadPasskeys();
  return keys.length;
}

/**
 * Synchronously check if any passkeys are registered (uses in-memory cache)
 * @returns {boolean} True if at least one passkey is registered
 */
function hasPasskeysSync() {
  return Array.isArray(passkeys) && passkeys.length > 0;
}

module.exports = {
  getAllPasskeys,
  getPasskey,
  addPasskey,
  updatePasskey,
  removePasskey,
  getPasskeyCount,
  hasPasskeysSync,
  loadPasskeys
};
