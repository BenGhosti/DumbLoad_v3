/**
 * VirusTotal scan service (optional, async background scanning).
 * Primary strategy: compute the local SHA-256 hash and look it up on
 * VirusTotal - NO file content is uploaded for known files (privacy-safe,
 * works for any file size, cheap on the free-tier quota).
 * Only when the hash is unknown AND VIRUSTOTAL_UPLOAD_UNKNOWN=true is the
 * file uploaded for a fresh analysis.
 *
 * API key rotation: VIRUSTOTAL_API_KEY accepts a comma-separated list of
 * keys ("key1,key2,..."). Each key has its own rate-limit window; when one
 * key hits its limit (HTTP 204/429) or is invalid (HTTP 401), the next key
 * is used automatically. Uploads are never blocked - a scan is skipped when
 * no key has a free slot.
 */

const crypto = require('crypto');
const fs = require('fs');
const { config } = require('../config');
const logger = require('../utils/logger');
const { updateGuestUploadScanStatus, removeGuestUpload } = require('../utils/guestPins');

const VT_BASE = 'https://www.virustotal.com/api/v3';
const MAX_POLLS = 10;
const POLL_INTERVAL_MS = 15000;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 4;
const RATE_LIMIT_MAX_WAIT_MS = 45000;
const EXHAUSTED_COOLDOWN_MS = 60 * 1000; // how long a key is parked after 204/429
const INVALID_KEY_COOLDOWN_MS = 10 * 60 * 1000; // how long a key is parked after 401

// Per-key state: key -> { timestamps: number[], exhaustedUntil: number }
const keyState = new Map();

/**
 * The configured VirusTotal API keys (array).
 * @returns {string[]}
 */
function getApiKeys() {
  return config.virustotalApiKeys || [];
}

/**
 * Check whether VirusTotal scanning is enabled and at least one key is set.
 * @returns {boolean}
 */
function isVirusTotalEnabled() {
  return config.virustotalEnabled && getApiKeys().length > 0;
}

/**
 * Prune expired entries for a key and return its current state.
 * @param {string} key - API key
 * @returns {{timestamps: number[], exhaustedUntil: number}}
 */
function getKeyState(key) {
  const now = Date.now();
  let state = keyState.get(key);
  if (!state) {
    state = { timestamps: [], exhaustedUntil: 0 };
    keyState.set(key, state);
  }
  state.timestamps = state.timestamps.filter(t => t >= now - RATE_LIMIT_WINDOW_MS);
  if (state.exhaustedUntil <= now) state.exhaustedUntil = 0;
  return state;
}

/**
 * Whether a key currently has a free rate-limit slot.
 * @param {string} key - API key
 * @returns {boolean}
 */
function keyHasSlot(key) {
  const state = getKeyState(key);
  return state.exhaustedUntil === 0 && state.timestamps.length < RATE_LIMIT_MAX_REQUESTS;
}

/**
 * Pick the first key with a free slot.
 * @returns {string|null}
 */
function pickApiKey() {
  for (const key of getApiKeys()) {
    if (keyHasSlot(key)) return key;
  }
  return null;
}

/**
 * Wait until any key has a free slot (max RATE_LIMIT_MAX_WAIT_MS).
 * @returns {Promise<string|null>} A usable key or null if waiting would take too long
 */
async function waitForApiKey() {
  const start = Date.now();
  while (Date.now() - start < RATE_LIMIT_MAX_WAIT_MS) {
    const key = pickApiKey();
    if (key) return key;
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
  return null;
}

/**
 * Record a request against a key (consumes one rate-limit slot).
 * @param {string} key - API key
 */
function recordRequest(key) {
  const state = getKeyState(key);
  state.timestamps.push(Date.now());
}

/**
 * Park a key for a while (rate limit hit or invalid key).
 * @param {string} key - API key
 * @param {number} durationMs - Cooldown duration
 */
function parkKey(key, durationMs) {
  const state = getKeyState(key);
  state.exhaustedUntil = Date.now() + durationMs;
  logger.warn(`VirusTotal: key "${maskKey(key)}" parked for ${Math.round(durationMs / 1000)}s`);
}

/**
 * Mask a key for logs (show only the last 4 chars).
 * @param {string} key - API key
 * @returns {string}
 */
function maskKey(key) {
  return key.length > 4 ? `…${key.slice(-4)}` : '…';
}

/**
 * Central API request with key rotation.
 * Retries on rate-limit (204/429) or invalid-key (401) responses using the
 * next available key.
 * @param {string} path - API path (e.g. /files/<hash>)
 * @param {Object} [init] - fetch options (method, headers, body)
 * @returns {Promise<{response?: Response, status?: string, error?: string}>}
 */
async function apiRequest(path, init = {}) {
  const attempts = Math.max(1, getApiKeys().length * 2);
  for (let attempt = 0; attempt < attempts; attempt++) {
    const key = await waitForApiKey();
    if (!key) return { status: 'skipped', error: 'rate-limited' };
    recordRequest(key);
    let response;
    try {
      response = await fetch(`${VT_BASE}${path}`, {
        ...init,
        headers: { ...(init.headers || {}), 'x-apikey': key },
      });
    } catch (err) {
      return { status: 'error', error: err.message };
    }
    if (response.status === 204 || response.status === 429) {
      parkKey(key, EXHAUSTED_COOLDOWN_MS);
      continue; // try the next key
    }
    if (response.status === 401) {
      parkKey(key, INVALID_KEY_COOLDOWN_MS);
      continue; // try the next key
    }
    return { response };
  }
  return { status: 'skipped', error: 'rate-limited' };
}

/**
 * Compute the SHA-256 hash of a file by streaming (constant memory).
 * @param {string} filePath - Absolute path
 * @returns {Promise<string>} Hex SHA-256
 */
function hashFile(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', reject);
  });
}

/**
 * Look up a file hash on VirusTotal. Sends only the SHA-256, never content.
 * @param {string} sha256 - Hex SHA-256 of the file
 * @returns {Promise<{status: 'ok'|'found'|'not-found'|'error'|'skipped', malicious?: number, total?: number, error?: string}>}
 */
async function lookupHash(sha256) {
  const { response, status, error } = await apiRequest(`/files/${sha256}`);
  if (status) return { status, error };
  if (response.status === 404) {
    return { status: 'not-found' };
  }
  if (!response.ok) {
    logger.error(`VirusTotal hash lookup failed: HTTP ${response.status}`);
    return { status: 'error', error: `HTTP ${response.status}` };
  }
  const json = await response.json();
  const attrs = json?.data?.attributes || {};
  const stats = attrs.last_analysis_stats || {};
  const malicious = stats.malicious || 0;
  const total = (stats.harmless || 0) + (stats.malicious || 0) +
    (stats.suspicious || 0) + (stats.undetected || 0);
  if (malicious >= config.virustotalMinMaliciousEngines) {
    logger.warn(`VirusTotal: malware detected for hash ${sha256.slice(0, 12)}… (${malicious}/${total} engines)`);
    return { status: 'found', malicious, total };
  }
  return { status: 'ok', malicious, total };
}

/**
 * Upload a file to VirusTotal for analysis (fallback path, opt-in).
 * @param {string} filePath - Absolute path
 * @param {string} filename - Original filename
 * @returns {Promise<string|null>} Analysis ID or null on failure
 */
async function uploadFile(filePath, filename) {
  const data = await fs.promises.readFile(filePath);
  const form = new FormData();
  form.append('file', new Blob([data]), filename || 'upload.bin');
  const { response, status } = await apiRequest('/files', { method: 'POST', body: form });
  if (status || !response.ok) {
    if (response) logger.error(`VirusTotal upload failed: HTTP ${response.status}`);
    return null;
  }
  const json = await response.json();
  return json?.data?.id || null;
}

/**
 * Fetch the analysis result for an analysis ID.
 * @param {string} analysisId - VirusTotal analysis ID
 * @returns {Promise<Object|null>} { status, stats } or null on failure
 */
async function fetchAnalysis(analysisId) {
  const { response, status } = await apiRequest(`/analyses/${analysisId}`);
  if (status || !response.ok) return null;
  const json = await response.json();
  const attributes = json?.data?.attributes || {};
  return {
    status: attributes.status,
    stats: attributes.stats || {},
  };
}

/**
 * Upload a file and poll until a verdict is available (fallback path).
 * @param {string} filePath - Absolute path
 * @param {string} filename - Original filename
 * @returns {Promise<{status: 'ok'|'found'|'error'|'skipped', malicious?: number, total?: number, error?: string}>}
 */
async function scanByUpload(filePath, filename) {
  try {
    const size = (await fs.promises.stat(filePath)).size;
    if (size > config.virustotalMaxFileSizeBytes) {
      logger.info(`VirusTotal: file ${filename} (${size} bytes) exceeds upload limit, skipping`);
      return { status: 'skipped', error: 'too-large' };
    }
    const analysisId = await uploadFile(filePath, filename);
    if (!analysisId) return { status: 'skipped', error: 'upload-failed' };

    for (let i = 0; i < MAX_POLLS; i++) {
      if (i > 0) {
        await new Promise(resolve => setTimeout(resolve, POLL_INTERVAL_MS));
      }
      const result = await fetchAnalysis(analysisId);
      if (!result) return { status: 'skipped', error: 'fetch-failed' };
      if (result.status === 'completed') {
        const malicious = result.stats.malicious || 0;
        const total = (result.stats.harmless || 0) + (result.stats.malicious || 0) +
          (result.stats.suspicious || 0) + (result.stats.undetected || 0);
        if (malicious >= config.virustotalMinMaliciousEngines) {
          logger.warn(`VirusTotal: malware detected in ${filename}: ${malicious}/${total} engines`);
          return { status: 'found', malicious, total };
        }
        return { status: 'ok', malicious, total };
      }
    }
    logger.warn(`VirusTotal: analysis of ${filename} did not complete in time, marking pending`);
    return { status: 'skipped', error: 'timeout' };
  } catch (err) {
    logger.error(`VirusTotal scan error for ${filename}: ${err.message}`);
    return { status: 'error', error: err.message };
  }
}

/**
 * Scan a file via VirusTotal: hash lookup first, upload only as an opt-in
 * fallback for unknown hashes.
 * @param {string} filePath - Absolute path
 * @param {string} filename - Original filename
 * @returns {Promise<{status: 'ok'|'found'|'unknown'|'error'|'skipped', malicious?: number, total?: number, sha256?: string, error?: string}>}
 */
async function scanFile(filePath, filename = 'upload.bin') {
  if (!isVirusTotalEnabled()) {
    return { status: 'skipped', error: 'vt-disabled' };
  }
  try {
    const sha256 = await hashFile(filePath);
    const lookup = await lookupHash(sha256);

    if (lookup.status === 'found' || lookup.status === 'ok') {
      return { ...lookup, sha256 };
    }
    if (lookup.status === 'not-found') {
      if (config.virustotalUploadUnknown) {
        const result = await scanByUpload(filePath, filename);
        return { ...result, sha256 };
      }
      logger.info(`VirusTotal: hash ${sha256.slice(0, 12)}… not analyzed yet, marking unknown`);
      return { status: 'unknown', sha256 };
    }
    return { ...lookup, sha256 };
  } catch (err) {
    logger.error(`VirusTotal scan error for ${filename}: ${err.message}`);
    return { status: 'error', error: err.message };
  }
}

/**
 * Fire-and-forget background scan of a completed upload.
 * Deletes the file if a malware verdict arrives; updates the guest upload log.
 * @param {Object} ctx - { filePath, filename, isGuest, guestId, uploadLogId }
 */
function queueVirusTotalScan(ctx) {
  if (!isVirusTotalEnabled()) return;
  // Run detached (never blocks the upload response)
  const run = async () => {
    const result = await scanFile(ctx.filePath, ctx.filename);
    let logStatus = 'vt-skipped';
    if (result.status === 'ok') logStatus = 'vt-ok';
    else if (result.status === 'found') logStatus = 'vt-found';
    else if (result.status === 'unknown') logStatus = 'vt-unknown';
    else if (result.status === 'error') logStatus = 'vt-error';

    if (ctx.isGuest && ctx.guestId && ctx.uploadLogId) {
      await updateGuestUploadScanStatus(ctx.guestId, ctx.uploadLogId, logStatus).catch(() => {});
    }

    if (result.status === 'found') {
      logger.warn(`VirusTotal: deleting infected upload ${ctx.filePath}`);
      fs.promises.unlink(ctx.filePath).catch(err => {
        logger.error(`VirusTotal: failed to delete infected file ${ctx.filePath}: ${err.message}`);
      });
      if (ctx.isGuest && ctx.guestId && ctx.uploadLogId) {
        await removeGuestUpload(ctx.guestId, ctx.uploadLogId).catch(() => {});
      }
    }
  };
  run().catch(err => {
    logger.error(`VirusTotal background scan failed: ${err.message}`);
  });
}

module.exports = {
  isVirusTotalEnabled,
  getApiKeys,
  hashFile,
  lookupHash,
  scanFile,
  queueVirusTotalScan,
};
