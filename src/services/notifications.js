/**
 * Notification service for file upload events.
 * Integrates with Apprise for sending notifications about uploads.
 * Handles message formatting and notification delivery.
 */

const { spawn } = require('child_process');
const { formatFileSize, calculateDirectorySize, sanitizeFilename } = require('../utils/fileUtils');
const logger = require('../utils/logger');

/**
 * Send a notification using Apprise
 * @param {string} filename - Name of uploaded file
 * @param {number} fileSize - Size of uploaded file in bytes
 * @param {Object} config - Configuration object
 * @returns {Promise<void>}
 */
async function sendNotification(filename, fileSize, config) {
    const { appriseUrl, appriseMessage, appriseSizeUnit, uploadDir } = config;

    console.debug("NOTIFICATIONS CONFIG:", filename, fileSize, config);
    if (!appriseUrl) {
        return;
    }

    try {
        const formattedSize = formatFileSize(fileSize, appriseSizeUnit);
        const dirSize = await calculateDirectorySize(uploadDir);
        const totalStorage = formatFileSize(dirSize);

        // Sanitize the filename to remove any special characters that could cause issues
        const sanitizedFilename = sanitizeFilename(filename); // apply sanitization of filename again (in case)
        
        // Construct the notification message by replacing placeholders
        const message = appriseMessage
            .replace('{filename}', sanitizedFilename)
            .replace('{size}', formattedSize)
            .replace('{storage}', totalStorage);

        await new Promise((resolve, reject) => {
            const appriseProcess = spawn('apprise', [appriseUrl, '-b', message]);

            appriseProcess.stdout.on('data', (data) => {
                logger.info(`Apprise Output: ${data.toString().trim()}`);
            });

            appriseProcess.stderr.on('data', (data) => {
                logger.error(`Apprise Error: ${data.toString().trim()}`);
            });

            appriseProcess.on('close', (code) => {
                if (code === 0) {
                    logger.info(`Notification sent for: ${sanitizedFilename} (${formattedSize}, Total storage: ${totalStorage})`);
                    resolve();
                } else {
                    reject(new Error(`Apprise process exited with code ${code}`));
                }
            });

            appriseProcess.on('error', (err) => {
                reject(new Error(`Apprise process failed to start: ${err.message}`));
            });
        });
    } catch (err) {
        logger.error(`Failed to send notification: ${err.message}`);
    }
}

module.exports = {
    sendNotification,
};