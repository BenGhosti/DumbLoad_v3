/**
 * ClamAV scan client for clamd (no external dependency).
 * Streams files to clamd using the INSTREAM protocol over TCP.
 * Used for malware scanning of uploads (scope: off/guest/all).
 */

const net = require('net');
const fs = require('fs');
const { config } = require('../config');
const logger = require('../utils/logger');

const CHUNK_SIZE = 64 * 1024;

/**
 * Determine whether a file should be scanned by ClamAV based on scope.
 * @param {boolean} isGuest - Whether the upload comes from a guest session
 * @returns {boolean} True if ClamAV scan applies
 */
function shouldScanClamav(isGuest) {
  if (config.clamavScanEnabled === 'all') return true;
  if (config.clamavScanEnabled === 'guest') return isGuest;
  return false;
}

/**
 * Scan a file via clamd INSTREAM protocol.
 * @param {string} filePath - Absolute path of the file to scan
 * @param {Object} [options] - Optional overrides: { host, port, timeoutMs }
 * @returns {Promise<{status: 'ok'|'found'|'error', signature?: string, error?: string}>}
 */
function scanFile(filePath, options = {}) {
  return new Promise((resolve) => {
    const host = options.host || config.clamavHost;
    const port = options.port || config.clamavPort;
    const timeoutMs = options.timeoutMs || config.clamavTimeoutMs;

    const socket = net.createConnection({
      host,
      port,
    });

    let response = '';
    let settled = false;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };

    socket.setTimeout(timeoutMs);
    socket.on('timeout', () => {
      logger.error(`ClamAV scan timed out after ${timeoutMs}ms (${filePath})`);
      finish({ status: 'error', error: 'clamd timeout' });
    });

    socket.on('error', (err) => {
      logger.error(`ClamAV connection error: ${err.message}`);
      finish({ status: 'error', error: err.message });
    });

    socket.on('connect', () => {
      const stream = fs.createReadStream(filePath, { highWaterMark: CHUNK_SIZE });
      socket.write('zINSTREAM\0');
      stream.on('data', (chunk) => {
        const len = Buffer.alloc(4);
        len.writeUInt32BE(chunk.length, 0);
        socket.write(len);
        socket.write(chunk);
      });
      stream.on('error', (err) => {
        logger.error(`ClamAV: failed reading file ${filePath}: ${err.message}`);
        finish({ status: 'error', error: err.message });
      });
      stream.on('end', () => {
        socket.write(Buffer.alloc(4, 0)); // zero-length chunk = end of stream
      });
    });

    socket.on('data', (data) => {
      response += data.toString('utf8');
      if (response.includes('\0')) {
        const lines = response.split('\0').join('').split('\n').filter(Boolean);
        const lastLine = lines.length > 0 ? lines[lines.length - 1].trim() : '';
        if (/ FOUND$/.test(lastLine)) {
          const signature = lastLine.replace(/ FOUND$/, '').split(': ').pop();
          logger.warn(`ClamAV: malware detected in ${filePath}: ${signature}`);
          finish({ status: 'found', signature });
        } else if (/^stream: OK$/.test(lastLine)) {
          finish({ status: 'ok' });
        }
      }
    });
  });
}

/**
 * Scan a file and normalize the outcome for upload handling.
 * - clamd down: fail-open (accept + warn) or fail-closed (reject) per config
 * @param {string} filePath - Absolute path
 * @returns {Promise<{ok: boolean, status: string, signature?: string, error?: string}>}
 */
async function runClamavScan(filePath) {
  const result = await scanFile(filePath);
  if (result.status === 'ok') {
    return { ok: true, status: 'clamav-ok' };
  }
  if (result.status === 'found') {
    return { ok: false, status: 'clamav-found', signature: result.signature };
  }
  // error case (unreachable/timeout/read error)
  if (config.clamavFailOpen) {
    logger.warn(`ClamAV scan failed for ${filePath} (${result.error}) - FAIL_OPEN: accepting upload`);
    return { ok: true, status: 'clamav-error', error: result.error };
  }
  logger.warn(`ClamAV scan failed for ${filePath} (${result.error}) - FAIL_CLOSED: rejecting upload`);
  return { ok: false, status: 'clamav-error', error: result.error };
}

module.exports = {
  shouldScanClamav,
  scanFile,
  runClamavScan,
};
