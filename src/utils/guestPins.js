/**
 * Guest PIN storage and verification.
 * Guest PINs allow time-limited, usage-limited upload access.
 * PINs are stored only as scrypt hashes; the plain PIN is shown exactly
 * once at creation time and never persisted.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { config } = require('../config');
const logger = require('../utils/logger');

const MAX_UPLOAD_LOG_ENTRIES = 100;

let guestPins = null; // In-memory cache: array of guest PIN records

/**
 * Check whether the guest PIN feature is effectively enabled
 * (env flag set AND a master PIN exists, since guest PINs share its length).
 * @returns {boolean}
 */
function isGuestFeatureEnabled() {
  return config.guestPinEnabled && !!config.pin;
}

/**
 * Generate a random numeric PIN of the same length as the master PIN.
 * @returns {string} PIN (digits only)
 */
function generateGuestPin() {
  const length = config.pin ? config.pin.length : 4;
  let pin = '';
  for (let i = 0; i < length; i++) {
    pin += crypto.randomInt(0, 10).toString();
  }
  return pin;
}

/**
 * Hash a guest PIN with a fresh random salt (scrypt).
 * @param {string} pin - Plain PIN (digits)
 * @returns {Promise<string>} Encoded hash: scrypt$<saltB64>$<hashB64>
 */
async function hashPin(pin) {
  const salt = crypto.randomBytes(16);
  return new Promise((resolve, reject) => {
    crypto.scrypt(pin, salt, 64, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(`scrypt$${salt.toString('base64')}$${derivedKey.toString('base64')}`);
    });
  });
}

/**
 * Verify a plain PIN against an encoded scrypt hash.
 * @param {string} pin - Plain PIN candidate
 * @param {string} encoded - Encoded hash (scrypt$salt$hash)
 * @returns {Promise<boolean>}
 */
async function verifyPinHash(pin, encoded) {
  if (!pin || !encoded || typeof encoded !== 'string') return false;
  const parts = encoded.split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  const salt = Buffer.from(parts[1], 'base64');
  const expected = Buffer.from(parts[2], 'base64');
  return new Promise((resolve, reject) => {
    crypto.scrypt(pin, salt, expected.length, (err, derivedKey) => {
      if (err) return reject(err);
      try {
        resolve(crypto.timingSafeEqual(derivedKey, expected));
      } catch {
        resolve(false);
      }
    });
  });
}

/**
 * Load guest PINs from disk (lazy, cached)
 * @returns {Promise<Array>} Array of guest PIN records
 */
async function loadGuestPins() {
  if (guestPins !== null) return guestPins;
  try {
    const data = await fs.promises.readFile(config.guestPinsFilePath, 'utf8');
    guestPins = JSON.parse(data);
    if (!Array.isArray(guestPins)) guestPins = [];
    logger.info(`Loaded ${guestPins.length} guest PIN(s) from storage`);
  } catch (err) {
    if (err.code === 'ENOENT') {
      guestPins = [];
      logger.info('No guest PIN storage file found, starting with empty list');
    } else {
      logger.error(`Failed to load guest PINs: ${err.message}`);
      guestPins = [];
    }
  }
  return guestPins;
}

/**
 * Save guest PINs to disk (atomic write)
 * @param {Array} pins - Array of guest PIN records
 */
async function saveGuestPins(pins) {
  guestPins = pins;
  const tempPath = `${config.guestPinsFilePath}.${Date.now()}.tmp`;
  try {
    await fs.promises.mkdir(path.dirname(config.guestPinsFilePath), { recursive: true });
    await fs.promises.writeFile(tempPath, JSON.stringify(pins, null, 2));
    await fs.promises.rename(tempPath, config.guestPinsFilePath);
  } catch (err) {
    logger.error(`Failed to save guest PINs: ${err.message}`);
    try { await fs.promises.unlink(tempPath); } catch { /* ignore */ }
    throw err;
  }
}

/**
 * Short ID for a guest PIN record (8 hex chars)
 */
function generatePinId() {
  return crypto.randomBytes(4).toString('hex');
}

/**
 * Get all guest PIN records (public view, without the hash)
 * @returns {Promise<Array>} Public-facing records
 */
async function getAllGuestPins() {
  const pins = await loadGuestPins();
  return pins.map(toPublicRecord);
}

/**
 * Get a single guest PIN record by ID (internal, includes hash)
 * @param {string} id - PIN record ID
 * @returns {Promise<Object|null>} Record or null
 */
async function getGuestPinById(id) {
  if (!id || typeof id !== 'string') return null;
  const pins = await loadGuestPins();
  return pins.find(p => p.id === id) || null;
}

/**
 * Get a single guest PIN record by plain PIN (internal, includes hash).
 * Searches active records only (not expired/revoked/used-up).
 * @param {string} pin - Plain PIN
 * @returns {Promise<Object|null>} Record or null
 */
async function getGuestPinByPin(pin) {
  if (!pin || typeof pin !== 'string') return null;
  const pins = await loadGuestPins();
  for (const record of pins) {
    if (getPinStatus(record) !== 'active') continue;
    try {
      if (await verifyPinHash(pin, record.pinHash)) return record;
    } catch (err) {
      logger.error(`Guest PIN verification error: ${err.message}`);
    }
  }
  return null;
}

/**
 * Compute the status of a guest PIN record.
 * @param {Object} record - Guest PIN record
 * @returns {string} 'active' | 'expired' | 'used-up' | 'revoked'
 */
function getPinStatus(record) {
  if (!record) return 'revoked';
  if (record.revoked) return 'revoked';
  if (record.expiresAt && Date.now() > record.expiresAt) return 'expired';
  if (record.maxUploads > 0 && record.uploadCount >= record.maxUploads) return 'used-up';
  return 'active';
}

/**
 * Create a new guest PIN.
 * @param {Object} options
 * @param {number} [options.ttlMin] - TTL in minutes (default: config default)
 * @param {number} [options.maxUploads] - Max uploads, 0 = unlimited (default: config default)
 * @param {number} [options.maxTotalBytes] - Total byte quota, 0 = unlimited (default: config default)
 * @returns {Promise<Object>} { pin, id, expiresAt, ... } - plain PIN is returned ONCE here
 */
async function createGuestPin({ ttlMin, maxUploads, maxTotalBytes } = {}) {
  const pin = generateGuestPin();
  const pinHash = await hashPin(pin);
  const ttl = (ttlMin && ttlMin > 0) ? ttlMin * 60 * 1000 : config.guestPinTtlDefaultMs;
  const record = {
    id: generatePinId(),
    pinHash,
    name: '',
    createdAt: Date.now(),
    expiresAt: Date.now() + ttl,
    maxUploads: (maxUploads && maxUploads > 0) ? Math.floor(maxUploads) : 0,
    uploadCount: 0,
    maxTotalBytes: (maxTotalBytes && maxTotalBytes > 0) ? Math.floor(maxTotalBytes) : 0,
    totalBytes: 0,
    revoked: false,
    lastUploadAt: null,
    uploads: [],
  };
  const pins = await loadGuestPins();
  pins.push(record);
  await saveGuestPins(pins);
  logger.info(`Created guest PIN ${record.id} (ttl ${ttl / 60000} min, maxUploads ${record.maxUploads || 'unlimited'})`);
  return { ...toPublicRecord(record), pin };
}

/**
 * Revoke a guest PIN immediately.
 * @param {string} id - PIN record ID
 * @returns {Promise<boolean>} True if revoked
 */
async function revokeGuestPin(id) {
  const pins = await loadGuestPins();
  const record = pins.find(p => p.id === id);
  if (!record) return false;
  record.revoked = true;
  await saveGuestPins(pins);
  logger.info(`Revoked guest PIN ${id}`);
  return true;
}

/**
 * Permanently delete a guest PIN record (e.g. used-up or expired PINs).
 * Warning: removes the record including its upload log.
 * @param {string} id - PIN record ID
 * @returns {Promise<boolean>} True if deleted
 */
async function deleteGuestPin(id) {
  const pins = await loadGuestPins();
  const index = pins.findIndex(p => p.id === id);
  if (index === -1) return false;
  pins.splice(index, 1);
  await saveGuestPins(pins);
  logger.info(`Deleted guest PIN ${id}`);
  return true;
}

/**
 * Update fields of a guest PIN record (internal; used by quota accounting
 * and tests).
 * @param {string} id - PIN record ID
 * @param {Object} updates - Fields to update
 * @returns {Promise<boolean>} True if updated
 */
async function updateGuestPin(id, updates) {
  const pins = await loadGuestPins();
  const record = pins.find(p => p.id === id);
  if (!record) return false;
  Object.assign(record, updates);
  await saveGuestPins(pins);
  return true;
}

/**
 * Record a successful, scan-approved guest upload and consume quota.
 * Only call AFTER the upload fully finished and passed the ClamAV scan.
 * @param {string} id - PIN record ID
 * @param {number} size - File size in bytes
 * @param {Object} info - { filename, scanStatus }
 * @returns {Promise<Object|null>} The created upload log entry, or null if the record is gone
 */
async function recordGuestUpload(id, size, info = {}) {
  const pins = await loadGuestPins();
  const record = pins.find(p => p.id === id);
  if (!record) return null;
  const entry = {
    id: crypto.randomBytes(6).toString('hex'),
    filename: info.filename || 'unknown',
    size,
    at: Date.now(),
    scanStatus: info.scanStatus || 'ok',
  };
  record.uploads = record.uploads.concat(entry).slice(-MAX_UPLOAD_LOG_ENTRIES);
  record.uploadCount += 1;
  record.totalBytes += size;
  record.lastUploadAt = Date.now();
  await saveGuestPins(pins);
  logger.info(`Guest PIN ${id}: recorded upload ${entry.filename} (${size} bytes)`);
  return entry;
}

/**
 * Update the VirusTotal scan status of an existing upload log entry.
 * @param {string} id - PIN record ID
 * @param {string} uploadLogId - Upload log entry ID
 * @param {string} vtStatus - e.g. 'vt-ok', 'vt-found', 'vt-error', 'vt-skipped'
 * @returns {Promise<boolean>} True if updated
 */
async function updateGuestUploadScanStatus(id, uploadLogId, vtStatus) {
  const pins = await loadGuestPins();
  const record = pins.find(p => p.id === id);
  if (!record) return false;
  const entry = record.uploads.find(u => u.id === uploadLogId);
  if (!entry) return false;
  entry.scanStatus = vtStatus;
  await saveGuestPins(pins);
  return true;
}

/**
 * Remove a recorded guest upload (used when a later VirusTotal verdict
 * deletes the file).
 * @param {string} id - PIN record ID
 * @param {string} uploadLogId - Upload log entry ID
 * @returns {Promise<boolean>} True if removed
 */
async function removeGuestUpload(id, uploadLogId) {
  const pins = await loadGuestPins();
  const record = pins.find(p => p.id === id);
  if (!record) return false;
  const index = record.uploads.findIndex(u => u.id === uploadLogId);
  if (index === -1) return false;
  record.uploads.splice(index, 1);
  record.uploadCount = Math.max(0, record.uploadCount - 1);
  await saveGuestPins(pins);
  return true;
}

/**
 * Strip the hash and internal fields for public/API use.
 */
function toPublicRecord(record) {
  if (!record) return null;
  const rest = { ...record };
  delete rest.pinHash;
  return {
    ...rest,
    status: getPinStatus(record),
  };
}

/**
 * Clean up expired guest PIN records that were never used (keeps used PINs
 * so the upload log stays available in the admin UI).
 */
async function cleanupExpiredGuestPins() {
  const pins = await loadGuestPins();
  const now = Date.now();
  const before = pins.length;
  const cleaned = pins.filter(p => {
    if (p.expiresAt && now > p.expiresAt && (!p.uploads || p.uploads.length === 0) && !p.revoked) {
      return false;
    }
    return true;
  });
  if (cleaned.length !== before) {
    await saveGuestPins(cleaned);
    logger.info(`Cleaned up ${before - cleaned.length} unused expired guest PIN(s)`);
  }
  return before - cleaned.length;
}

// Periodic cleanup of unused expired PINs (every 10 minutes)
let cleanupInterval;
function startGuestPinCleanup() {
  if (cleanupInterval) clearInterval(cleanupInterval);
  cleanupInterval = setInterval(() => {
    cleanupExpiredGuestPins().catch(err => {
      logger.error(`Guest PIN cleanup failed: ${err.message}`);
    });
  }, 10 * 60 * 1000);
  cleanupInterval.unref();
  return cleanupInterval;
}
function stopGuestPinCleanup() {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
    cleanupInterval = null;
  }
}
if (!process.env.DISABLE_BATCH_CLEANUP) {
  startGuestPinCleanup();
}

module.exports = {
  isGuestFeatureEnabled,
  generateGuestPin,
  hashPin,
  verifyPinHash,
  loadGuestPins,
  saveGuestPins,
  getAllGuestPins,
  getGuestPinById,
  getGuestPinByPin,
  getPinStatus,
  createGuestPin,
  revokeGuestPin,
  deleteGuestPin,
  updateGuestPin,
  recordGuestUpload,
  updateGuestUploadScanStatus,
  removeGuestUpload,
  cleanupExpiredGuestPins,
  startGuestPinCleanup,
  stopGuestPinCleanup,
};
