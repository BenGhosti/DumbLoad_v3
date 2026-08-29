/**
 * Guest PIN management routes (admin only).
 * Create, list, revoke guest PINs and view their upload logs.
 * The plain PIN is returned exactly once at creation and never stored.
 */

const express = require('express');
const router = express.Router();
const { config } = require('../config');
const logger = require('../utils/logger');
const {
  isGuestFeatureEnabled,
  getAllGuestPins,
  getGuestPinById,
  createGuestPin,
  revokeGuestPin,
  deleteGuestPin,
} = require('../utils/guestPins');

const MAX_TTL_MIN = 7 * 24 * 60; // 7 days
const MAX_UPLOADS = 1000;
const MAX_TOTAL_MB = 65536;

/**
 * List all guest PINs (without hashes) plus defaults for the admin UI.
 */
router.get('/', async (req, res) => {
  try {
    if (!isGuestFeatureEnabled()) {
      return res.status(404).json({ error: 'Guest PIN feature is disabled' });
    }
    const pins = await getAllGuestPins();
    res.json({
      enabled: true,
      defaults: {
        ttlDefaultMin: config.guestPinTtlDefaultMs / 60000,
        maxUploadsDefault: config.guestPinMaxUploadsDefault,
        maxTotalBytesDefaultMB: config.guestPinMaxTotalBytesDefault / (1024 * 1024),
        pinLength: config.pin ? config.pin.length : 0,
      },
      pins,
    });
  } catch (err) {
    logger.error(`Failed to list guest PINs: ${err.message}`);
    res.status(500).json({ error: 'Failed to list guest PINs' });
  }
});

/**
 * Create a new guest PIN. Returns the plain PIN exactly once.
 */
router.post('/', async (req, res) => {
  try {
    if (!isGuestFeatureEnabled()) {
      return res.status(404).json({ error: 'Guest PIN feature is disabled' });
    }

    const { ttlMin, maxUploads, maxTotalBytesMB } = req.body || {};

    // TTL validation (minutes)
    let parsedTtl = parseInt(ttlMin, 10);
    if (isNaN(parsedTtl) || parsedTtl < 1) parsedTtl = Math.round(config.guestPinTtlDefaultMs / 60000);
    if (parsedTtl > MAX_TTL_MIN) parsedTtl = MAX_TTL_MIN;

    // Max uploads validation (0 = unlimited)
    let parsedMaxUploads = parseInt(maxUploads, 10);
    if (isNaN(parsedMaxUploads) || parsedMaxUploads < 0) parsedMaxUploads = config.guestPinMaxUploadsDefault;
    if (parsedMaxUploads > MAX_UPLOADS) parsedMaxUploads = MAX_UPLOADS;

    // Total quota validation in MB (0 = unlimited)
    let parsedMaxTotalBytes = 0;
    if (maxTotalBytesMB !== undefined && maxTotalBytesMB !== null && maxTotalBytesMB !== '') {
      const mb = parseInt(maxTotalBytesMB, 10);
      if (isNaN(mb) || mb < 0) {
        return res.status(400).json({ error: 'maxTotalBytesMB must be a positive number (or empty for default)' });
      }
      parsedMaxTotalBytes = mb > 0 ? mb * 1024 * 1024 : 0;
      if (mb > MAX_TOTAL_MB) parsedMaxTotalBytes = MAX_TOTAL_MB * 1024 * 1024;
    } else {
      parsedMaxTotalBytes = config.guestPinMaxTotalBytesDefault;
    }

    const created = await createGuestPin({
      ttlMin: parsedTtl,
      maxUploads: parsedMaxUploads,
      maxTotalBytes: parsedMaxTotalBytes,
    });

    logger.info(`Guest PIN created by admin: ${created.id}`);
    res.status(201).json({
      ...created,
      // The plain PIN is only visible this one time
      message: 'Store this PIN now - it will not be shown again',
    });
  } catch (err) {
    logger.error(`Failed to create guest PIN: ${err.message}`);
    res.status(500).json({ error: 'Failed to create guest PIN' });
  }
});

/**
 * Get the upload log for one guest PIN.
 */
router.get('/:id/uploads', async (req, res) => {
  try {
    if (!isGuestFeatureEnabled()) {
      return res.status(404).json({ error: 'Guest PIN feature is disabled' });
    }
    const record = await getGuestPinById(req.params.id);
    if (!record) {
      return res.status(404).json({ error: 'Guest PIN not found' });
    }
    res.json({ uploads: record.uploads || [] });
  } catch (err) {
    logger.error(`Failed to get guest upload log: ${err.message}`);
    res.status(500).json({ error: 'Failed to get guest upload log' });
  }
});

/**
 * Revoke or permanently delete a guest PIN.
 * DELETE /:id            -> revoke (keeps the record and upload log)
 * DELETE /:id?purge=1    -> permanently delete the record (used-up/expired cleanup)
 */
router.delete('/:id', async (req, res) => {
  try {
    if (!isGuestFeatureEnabled()) {
      return res.status(404).json({ error: 'Guest PIN feature is disabled' });
    }

    const purge = req.query.purge === '1' || req.query.purge === 'true';
    if (purge) {
      const ok = await deleteGuestPin(req.params.id);
      if (!ok) {
        return res.status(404).json({ error: 'Guest PIN not found' });
      }
      return res.json({ message: 'Guest PIN deleted' });
    }

    const ok = await revokeGuestPin(req.params.id);
    if (!ok) {
      return res.status(404).json({ error: 'Guest PIN not found' });
    }
    res.json({ message: 'Guest PIN revoked' });
  } catch (err) {
    logger.error(`Failed to revoke/delete guest PIN: ${err.message}`);
    res.status(500).json({ error: 'Failed to revoke/delete guest PIN' });
  }
});

module.exports = router;
