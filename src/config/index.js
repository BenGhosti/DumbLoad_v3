require('dotenv').config();

const { validatePin } = require('../utils/security');
const logger = require('../utils/logger');
const fs = require('fs'); // Get version from package.json

/**
 * Environment Variables Reference
 *
 * PORT                - Port for the server (default: 3000)
 * NODE_ENV            - Node environment (default: 'development')
 * BASE_URL            - Base URL for the app (default: http://localhost:${PORT})
 * UPLOAD_DIR          - Directory for uploads (Docker/production)
 * LOCAL_UPLOAD_DIR    - Directory for uploads (local dev, fallback: './local_uploads')
 * DUMBLOAD_CONFIG_DIR - Directory for app config (passkeys); defaults to upload dir
 * MAX_FILE_SIZE       - Max upload size in MB (default: 1024)
 * AUTO_UPLOAD         - Enable auto-upload (true/false, default: false)
 * SHOW_FILE_LIST      - Enable file listing in frontend (true/false, default: false)
 * DUMBLOAD_PIN        - Security PIN for uploads (required for protected endpoints)
 * APPRISE_URL         - Apprise notification URL (optional)
 * APPRISE_MESSAGE     - Notification message template (default provided)
 * APPRISE_SIZE_UNIT   - Size unit for notifications (optional)
 * ALLOWED_EXTENSIONS  - Comma-separated list of allowed file extensions (optional)
 * DUMBLOAD_AUTH_MODE  - Authentication mode: 'pin', 'passkey', or 'both' (default: 'pin')
 * DUMBLOAD_RP_ID      - WebAuthn Relying Party ID (default: hostname from BASE_URL)
 * DUMBLOAD_ADMIN_PATH - Secret admin path for passkey management (empty = disabled)
 */

// Helper for clear configuration logging
const logConfig = (message, level = 'info') => {
  const prefix = level === 'warning' ? '⚠️ WARNING:' : 'ℹ️ INFO:';
  console.log(`${prefix} CONFIGURATION: ${message}`);
};

// Default configurations
const DEFAULT_SITE_TITLE = 'DumbLoad';
const NODE_ENV = process.env.NODE_ENV || 'production';
const PORT = process.env.PORT || 3000;
// Normalize the base URL (always with trailing slash) BEFORE the config object is frozen
const rawBaseUrl = process.env.BASE_URL || `http://localhost:${PORT}`;
const BASE_URL = rawBaseUrl.endsWith('/') ? rawBaseUrl : rawBaseUrl + '/';
const DEFAULT_CLIENT_MAX_RETRIES = 5; // Default retry count
console.log('Loaded ENV:', {
  PORT,
  UPLOAD_DIR: process.env.UPLOAD_DIR,
  LOCAL_UPLOAD_DIR: process.env.LOCAL_UPLOAD_DIR,
  NODE_ENV,
  BASE_URL,
  ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS || '*',
});
const logAndReturn = (key, value, isDefault = false) => {
  logConfig(`${key}: ${value}${isDefault ? ' (default)' : ''}`);
  return value;
};

/**
 * Determine the upload directory based on environment variables.
 * Priority:
 *   1. UPLOAD_DIR (for Docker/production)
 *   2. LOCAL_UPLOAD_DIR (for local development)
 *   3. './local_uploads' (default fallback)
 * @returns {string} The upload directory path
 */
function determineUploadDirectory() {
  let uploadDir;
  if (process.env.UPLOAD_DIR) {
    uploadDir = process.env.UPLOAD_DIR;
    logConfig(`Upload directory set from UPLOAD_DIR: ${uploadDir}`);
  } else if (process.env.LOCAL_UPLOAD_DIR) {
    uploadDir = process.env.LOCAL_UPLOAD_DIR;
    logConfig(`Upload directory using LOCAL_UPLOAD_DIR fallback: ${uploadDir}`, 'warning');
  } else {
    uploadDir = './local_uploads';
    logConfig(`Upload directory using default fallback: ${uploadDir}`, 'warning');
  }
  logConfig(`Final upload directory path: ${require('path').resolve(uploadDir)}`);
  return uploadDir;
}

/**
 * Utility to detect if running in local development mode
 * Returns true if NODE_ENV is not 'production' and UPLOAD_DIR is not set (i.e., not Docker)
 */
function isLocalDevelopment() {
  return process.env.NODE_ENV !== 'production';
}

/**
 * Ensure the upload directory exists (for local development only)
 * Creates the directory if it does not exist
 */
function ensureLocalUploadDirExists(uploadDir) {
  if (!isLocalDevelopment()) return;
  try {
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
      logConfig(`Created local upload directory: ${uploadDir}`);
    } else {
      logConfig(`Local upload directory exists: ${uploadDir}`);
    }
  } catch (err) {
    logConfig(`Failed to create local upload directory: ${uploadDir}. Error: ${err.message}`, 'warning');
  }
}

// Determine and ensure upload directory (for local dev)
const resolvedUploadDir = determineUploadDirectory();
ensureLocalUploadDirExists(resolvedUploadDir);

// Config directory (passkeys etc.). Defaults to the upload directory for
// backward compatibility; in Docker/Unraid this is set to a dedicated appdata
// mount (e.g. /app/config) so config survives separately from uploaded files.
const resolvedConfigDir = process.env.DUMBLOAD_CONFIG_DIR || resolvedUploadDir;

/**
 * Application configuration
 * Loads and validates environment variables
 */
const config = {
  // =====================
  // =====================
  // Server settings
  // =====================
  /**
   * Port for the server (default: 3000)
   * Set via PORT in .env
   */
  port: PORT,
  /**
   * Node environment (default: 'production')
   * Set via NODE_ENV in .env
   */
  nodeEnv: NODE_ENV,
  /**
   * Base URL for the app (default: http://localhost:${PORT})
   * Set via BASE_URL in .env
   */
  baseUrl: BASE_URL,
  
  // =====================
  // =====================
  // Upload settings
  // =====================
  /**
   * Directory for uploads
   * Priority: UPLOAD_DIR (Docker/production) > LOCAL_UPLOAD_DIR (local dev) > './local_uploads' (fallback)
   */
  uploadDir: resolvedUploadDir,
  /**
   * Max upload size in bytes (default: 1024MB)
   * Set via MAX_FILE_SIZE in .env (in MB)
   */
  maxFileSize: (() => {
    const sizeInMB = parseInt(process.env.MAX_FILE_SIZE || '1024', 10);
    if (isNaN(sizeInMB) || sizeInMB <= 0) {
      throw new Error('MAX_FILE_SIZE must be a positive number');
    }
    return sizeInMB * 1024 * 1024; // Convert MB to bytes
  })(),
  /**
   * Enable auto-upload (true/false, default: false)
   * Set via AUTO_UPLOAD in .env
   */
  autoUpload: process.env.AUTO_UPLOAD === 'true',
  /**
   * Enable file listing in frontend (true/false, default: false)
   * Set via SHOW_FILE_LIST in .env
   */
  showFileList: process.env.SHOW_FILE_LIST === 'true',
  
  // =====================
  // =====================
  // Security
  // =====================
  /**
   * Security PIN for uploads (required for protected endpoints)
   * Set via DUMBLOAD_PIN in .env
   */
  pin: validatePin(process.env.DUMBLOAD_PIN),
  /**
   * Login session timeout in milliseconds.
   * Set via SESSION_TIMEOUT in .env (seconds), or "instant"/"0" for a
   * browser-session-only login (cookie cleared when the browser closes).
   * Defaults to 8 hours. 0 = instant (session cookie, no maxAge).
   */
  sessionTimeoutMs: (() => {
    const raw = (process.env.SESSION_TIMEOUT || '').trim();
    if (!raw) return 8 * 60 * 60 * 1000; // default 8h
    if (raw.toLowerCase() === 'instant' || raw === '0') return 0; // instant
    const seconds = parseInt(raw, 10);
    if (isNaN(seconds) || seconds <= 0) {
      logConfig(`Invalid SESSION_TIMEOUT value: "${raw}". Using default 8 hours.`, 'warning');
      return 8 * 60 * 60 * 1000;
    }
    return seconds * 1000;
  })(),
  /**
   * Trust proxy for X-Forwarded-For header (default: false for security)
   * Only enable if behind a trusted reverse proxy
   * Set via TRUST_PROXY in .env
   */
  trustProxy: process.env.TRUST_PROXY === 'true',
  /**
   * Comma-separated list of trusted proxy IPs (optional)
   * Restricts which proxies can set X-Forwarded-For header
   * Set via TRUSTED_PROXY_IPS in .env
   */
  trustedProxyIps: process.env.TRUSTED_PROXY_IPS ? 
    process.env.TRUSTED_PROXY_IPS.split(',').map(ip => ip.trim()) : 
    null,
  
  // =====================
  // =====================
  // UI settings
  // =====================
  /**
   * Site title - fixed to "DumbLoad" for a clean, consistent UI
   */
  siteTitle: DEFAULT_SITE_TITLE,
  
  // =====================
  // =====================
  // Notification settings
  // =====================
  /**
   * Apprise notification URL (optional)
   * Set via APPRISE_URL in .env
   */
  appriseUrl: process.env.APPRISE_URL,
  /**
   * Notification message template (default provided)
   * Set via APPRISE_MESSAGE in .env
   */
  appriseMessage: process.env.APPRISE_MESSAGE || 'New file uploaded - {filename} ({size}), Storage used {storage}',
  /**
   * Size unit for notifications (optional)
   * Set via APPRISE_SIZE_UNIT in .env
   */
  appriseSizeUnit: process.env.APPRISE_SIZE_UNIT,
  
  // =====================
  // =====================
  // File extensions
  // =====================
  /**
   * Allowed file extensions (comma-separated, optional)
   * Set via ALLOWED_EXTENSIONS in .env
   */
  allowedExtensions: process.env.ALLOWED_EXTENSIONS ? 
    process.env.ALLOWED_EXTENSIONS.split(',').map(ext => ext.trim().toLowerCase()) : 
    null,

  /**
   * Max number of retries for client-side chunk uploads (default: 5)
   * Set via CLIENT_MAX_RETRIES in .env
   */
  clientMaxRetries: (() => {
    const envValue = process.env.CLIENT_MAX_RETRIES;
    const defaultValue = DEFAULT_CLIENT_MAX_RETRIES;
    if (envValue === undefined) {
      return logAndReturn('CLIENT_MAX_RETRIES', defaultValue, true);
    }
    const retries = parseInt(envValue, 10);
    if (isNaN(retries) || retries < 0) {
      logConfig(
        `Invalid CLIENT_MAX_RETRIES value: "${envValue}". Using default: ${defaultValue}`,
        'warning',
      );
      return logAndReturn('CLIENT_MAX_RETRIES', defaultValue, true);
    }
    return logAndReturn('CLIENT_MAX_RETRIES', retries);
  })(),

  uploadPin: logAndReturn('UPLOAD_PIN', process.env.UPLOAD_PIN || null),

  // =====================
  // =====================
  // WebAuthn / Passkey settings
  // =====================
  /**
   * Authentication mode: 'pin', 'passkey', or 'both'
   * Set via DUMBLOAD_AUTH_MODE in .env
   */
  authMode: (() => {
    const mode = (process.env.DUMBLOAD_AUTH_MODE || 'pin').toLowerCase();
    return ['pin', 'passkey', 'both'].includes(mode) ? mode : 'pin';
  })(),
  /**
   * WebAuthn Relying Party ID (default: hostname from BASE_URL)
   * Set via DUMBLOAD_RP_ID in .env
   */
  rpId: (() => {
    if (process.env.DUMBLOAD_RP_ID) return process.env.DUMBLOAD_RP_ID;
    try {
      return new URL(BASE_URL).hostname;
    } catch (e) {
      return 'localhost';
    }
  })(),
  /**
   * WebAuthn Relying Party name
   */
  rpName: process.env.DUMBLOAD_RP_NAME || DEFAULT_SITE_TITLE,
  /**
   * WebAuthn Relying Party origin (default: BASE_URL origin)
   */
  rpOrigin: (() => {
    try {
      return new URL(BASE_URL).origin;
    } catch (e) {
      return BASE_URL;
    }
  })(),
  /**
   * Secret admin path for passkey management.
   * Empty/unset = admin DISABLED: no passkey can be registered or removed.
   * Set via DUMBLOAD_ADMIN_PATH in .env (e.g. /admin/passkeys)
   */
  adminPath: (process.env.DUMBLOAD_ADMIN_PATH || '').trim(),
  /**
   * Whether the passkey management admin page is enabled
   */
  adminEnabled: Boolean((process.env.DUMBLOAD_ADMIN_PATH || '').trim()),
  /**
   * Directory for persistent app configuration (passkeys etc.)
   * Priority: DUMBLOAD_CONFIG_DIR > upload directory (backward compatible)
   */
  configDir: resolvedConfigDir,
  /**
   * Path to the passkey storage file
   */
  passkeyFilePath: require('path').join(resolvedConfigDir, '.passkeys.json'),
};

console.log(`Upload directory configured as: ${config.uploadDir}`);

// Validate required settings
function validateConfig() {
  const errors = [];
  
  if (config.maxFileSize <= 0) {
    errors.push('MAX_FILE_SIZE must be greater than 0');
  }

  // Validate BASE_URL format (trailing slash is already normalized before freeze)
  try {
    new URL(config.baseUrl);
  } catch (err) {
    const errorMsg = `BASE_URL must be a valid URL: ${err.message || err}`;
    logger.error(errorMsg);
    errors.push(errorMsg);
  }

  // Warn when the WebAuthn RP ID is an IP address or not browser-friendly.
  // Browsers only allow passkeys over HTTPS with a hostname (or on localhost).
  const rpId = config.rpId;
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(rpId) || rpId.includes(':');
  if (config.authMode !== 'pin' && isIp && rpId !== 'localhost') {
    logger.warn(
      `WebAuthn RP ID "${rpId}" is an IP address. Browsers only allow passkeys on "localhost" ` +
      'or over HTTPS with a domain name. Passkey registration/login will likely fail ' +
      'until you access DumbLoad via a hostname (e.g. reverse proxy with HTTPS).'
    );
  }

  if (config.adminEnabled) {
    logger.info(`Passkey management enabled at: ${config.adminPath}`);
  } else {
    logger.info('Passkey management disabled (DUMBLOAD_ADMIN_PATH not set)');
  }
  
  if (config.nodeEnv === 'production') {
    if (!config.appriseUrl) {
      logger.info('Notifications disabled - No Configuration');
    }
  }
  
  if (errors.length > 0) {
    throw new Error('Configuration validation failed:\n' + errors.join('\n'));
  }
}

// Freeze configuration to prevent modifications
Object.freeze(config);

module.exports = {
  config,
  validateConfig
}; 