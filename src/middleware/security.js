/**
 * Security middleware implementations for HTTP-level protection.
 * Sets security headers (CSP, HSTS) and implements PIN-based authentication.
 * Provides Express middleware for securing routes and responses.
 */

const { safeCompare } = require('../utils/security');
const { isValidSession, createSession, SESSION_DURATION } = require('../utils/session');
const { config } = require('../config');
const { hasPasskeysSync } = require('../services/passkeyStore');
const logger = require('../utils/logger');
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

const SESSION_COOKIE_NAME = 'DUMBLOAD_SESSION';

// const { config } = require('../config');
/**
 * Security headers middleware
 * DEPRECATED: Use helmet middleware instead for security headers
 */
// function securityHeaders(req, res, next) {
//   // Content Security Policy
//   let csp =
//     "default-src 'self'; " +
//     "connect-src 'self'; " +
//     "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; " +
//     "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; " +
//     "img-src 'self' data: blob:;";

//   // If allowedIframeOrigins is set, allow those origins to embed via iframe
//   if (config.allowedIframeOrigins && config.allowedIframeOrigins.length > 0) {
//     // Remove X-Frame-Options header (do not set it)
//     // Add frame-ancestors directive to CSP
//     const frameAncestors = ["'self'", ...config.allowedIframeOrigins].join(' ');
//     csp += ` frame-ancestors ${frameAncestors};`;
//   } else {
//     // Default: only allow same origin if not configured
//     res.setHeader('X-Frame-Options', 'SAMEORIGIN');
//   }

//   res.setHeader('Content-Security-Policy', csp);
//   res.setHeader('X-Content-Type-Options', 'nosniff');
//   res.setHeader('X-XSS-Protection', '1; mode=block');

//   // Strict Transport Security (when in production)
//   if (process.env.NODE_ENV === 'production') {
//     res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
//   }

//   next();
// }

function getHelmetConfig() {
  // const isSecure = BASE_URL.startsWith('https://');
  
  return {
    noSniff: true, // Prevent MIME type sniffing
    frameguard: { action: 'deny' }, // Prevent clickjacking
    crossOriginEmbedderPolicy: false, // Disable for local network access
    crossOriginOpenerPolicy: false, // Disable to prevent warnings on HTTP
    crossOriginResourcePolicy: { policy: 'cross-origin' }, // Allow cross-origin for local network
    referrerPolicy: { policy: 'no-referrer-when-downgrade' }, // Set referrer policy
    ieNoOpen: true, // Prevent IE from executing downloads
    // hsts: isSecure ? { maxAge: 31536000, includeSubDomains: true } : false, // Only enforce HTTPS if using HTTPS
    // Disabled Helmet middlewares:
    hsts: false,
    contentSecurityPolicy: false, // Disable CSP for now
    dnsPrefetchControl: true, // Disable DNS prefetching
    permittedCrossDomainPolicies: false,
    originAgentCluster: false,
    xssFilter: false,
  };
}

/**
 * PIN protection middleware
 * @param {string} PIN - Valid PIN for comparison
 */
function requirePin(PIN) {
  return (req, res, next) => {
    // Skip PIN check if no PIN is configured
    if (!PIN) {
      return next();
    }

    // Check session token first (primary mechanism, 8h expiry)
    const sessionToken = req.cookies?.[SESSION_COOKIE_NAME];
    if (isValidSession(sessionToken)) {
      return next();
    }

    // Check legacy PIN cookie (backward compatibility)
    const cookiePin = req.cookies?.DUMBLOAD_PIN;
    if (cookiePin && safeCompare(cookiePin, PIN)) {
      // Migrate to session token for continued access
      const newToken = createSession(req.ip);
      res.cookie(SESSION_COOKIE_NAME, newToken, {
        httpOnly: true,
        secure: req.secure || (BASE_URL.startsWith('https') && NODE_ENV === 'production'),
        sameSite: 'strict',
        path: '/',
        maxAge: SESSION_DURATION
      });
      return next();
    }

    // Check header as fallback
    const headerPin = req.headers['x-pin'];
    if (headerPin && safeCompare(headerPin, PIN)) {
      // Set session cookie for subsequent requests
      const newToken = createSession(req.ip);
      res.cookie(SESSION_COOKIE_NAME, newToken, {
        httpOnly: true,
        secure: req.secure || (BASE_URL.startsWith('https') && NODE_ENV === 'production'),
        sameSite: 'strict',
        path: '/',
        maxAge: SESSION_DURATION
      });
      return next();
    }

    logger.warn(`Unauthorized access attempt from IP: ${req.ip}`);
    res.status(401).json({ error: 'Unauthorized' });
  };
}

/**
 * Determine whether authentication is required based on the configured auth mode
 * @returns {boolean} True if authentication is required
 */
function isAuthRequired() {
  const pinConfigured = !!config.pin;
  const passkeyConfigured = hasPasskeysSync();

  switch (config.authMode) {
    case 'passkey':
      return passkeyConfigured;
    case 'both':
      return pinConfigured || passkeyConfigured;
    case 'pin':
    default:
      return pinConfigured;
  }
}

/**
 * Unified authentication middleware for protected routes.
 * Supports PIN, Passkey, and both modes via session tokens.
 */
function requireAuth() {
  return (req, res, next) => {
    // If no auth is configured, allow access
    if (!isAuthRequired()) {
      return next();
    }

    // Check session token first (from PIN or Passkey login)
    const sessionToken = req.cookies?.[SESSION_COOKIE_NAME];
    if (isValidSession(sessionToken)) {
      return next();
    }

    // Fallback: legacy PIN cookie
    const cookiePin = req.cookies?.DUMBLOAD_PIN;
    if (config.pin && cookiePin && safeCompare(cookiePin, config.pin)) {
      const newToken = createSession(req.ip);
      res.cookie(SESSION_COOKIE_NAME, newToken, {
        httpOnly: true,
        secure: req.secure || (BASE_URL.startsWith('https') && NODE_ENV === 'production'),
        sameSite: 'strict',
        path: '/',
        maxAge: SESSION_DURATION
      });
      return next();
    }

    // Fallback: PIN header (for API clients)
    const headerPin = req.headers['x-pin'];
    if (config.pin && headerPin && safeCompare(headerPin, config.pin)) {
      const newToken = createSession(req.ip);
      res.cookie(SESSION_COOKIE_NAME, newToken, {
        httpOnly: true,
        secure: req.secure || (BASE_URL.startsWith('https') && NODE_ENV === 'production'),
        sameSite: 'strict',
        path: '/',
        maxAge: SESSION_DURATION
      });
      return next();
    }

    logger.warn(`Unauthorized access attempt from IP: ${req.ip}`);
    res.status(401).json({ error: 'Unauthorized' });
  };
}

module.exports = {
  // securityHeaders, // Deprecated, use helmet instead
  getHelmetConfig,
  requirePin,
  requireAuth,
  isAuthRequired
}; 