/**
 * Guest PIN tests.
 * Covers PIN creation, guest login, upload restrictions, quota, expiry,
 * revocation, and guest access to restricted endpoints.
 */

// Disable batch cleanup for tests
process.env.DISABLE_BATCH_CLEANUP = 'true';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

// Temp upload dir must exist and be set BEFORE requiring the app
const UPLOAD_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'dumbload-guest-test-'));

// Feature + auth config must be set BEFORE requiring the app
process.env.DUMBLOAD_PIN = '12345';
process.env.GUEST_PIN_ENABLED = 'true';
process.env.SHOW_FILE_LIST = 'true';
process.env.LOCAL_UPLOAD_DIR = UPLOAD_DIR;

const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const http = require('node:http');

const { app, initialize } = require('../src/app');
const { updateGuestPin } = require('../src/utils/guestPins');
const { pinVerifyLimiter } = require('../src/middleware/rateLimiter');

let server;
let baseUrl;
let cookieJar = ''; // shared cookie for guest sessions

before(async () => {
  await initialize();
  server = http.createServer(app);
  await new Promise((resolve) => {
    server.listen(0, () => {
      baseUrl = `http://127.0.0.1:${server.address().port}`;
      resolve();
    });
  });
});

after(async () => {
  if (server) {
    await new Promise((resolve) => server.close(resolve));
  }
  fs.rmSync(UPLOAD_DIR, { recursive: true, force: true });
});

beforeEach(() => {
  // Keep the PIN verification limiter from blocking the test flow
  try {
    pinVerifyLimiter.resetKey('127.0.0.1');
  } catch { /* ignore */ }
});

function makeRequest(options, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(baseUrl);
    const req = http.request({
      ...options,
      host: url.hostname,
      port: url.port,
      headers: { ...(options.headers || {}), ...headers },
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    if (body !== null && body !== undefined) {
      req.write(body);
    }
    req.end();
  });
}

function parseJson(text) {
  try { return JSON.parse(text); } catch { return null; }
}

async function jsonRequest(method, route, body, cookie = '') {
  const isBodyless = method === 'GET' || method === 'DELETE';
  const response = await makeRequest(
    {
      method,
      path: route,
      headers: {
        ...(!isBodyless ? { 'Content-Type': 'application/json' } : {}),
        Cookie: cookie,
      },
    },
    isBodyless ? null : JSON.stringify(body)
  );
  return { ...response, json: parseJson(response.body) };
}

async function adminLogin() {
  const response = await jsonRequest('POST', '/api/auth/verify-pin', { pin: '12345' });
  const setCookie = response.headers['set-cookie'];
  assert.ok(setCookie, 'admin login should set a session cookie');
  return setCookie.join('; ');
}

async function createGuestPin(body = {}, adminCookie) {
  const response = await jsonRequest('POST', '/api/guest-pins', body, adminCookie);
  return { ...response, json: parseJson(response.body) };
}

async function guestUpload(filename, content, cookie) {
  const initRes = await jsonRequest('POST', '/api/upload/init', { filename, fileSize: Buffer.byteLength(content) }, cookie);
  if (initRes.status !== 200) return { init: initRes };
  const uploadId = initRes.json.uploadId;
  const chunkRes = await makeRequest(
    { method: 'POST', path: `/api/upload/chunk/${uploadId}`, headers: { 'Content-Type': 'application/octet-stream', Cookie: cookie } },
    content
  );
  return { init: initRes, uploadId, chunk: { ...chunkRes, json: parseJson(chunkRes.body) } };
}

describe('Guest PIN feature', () => {
  let adminCookie;
  let guestPin; // { pin, id } from creation

  before(async () => {
    adminCookie = await adminLogin();
  });

  it('rejects guest PIN list without admin session', async () => {
    const res = await makeRequest({ method: 'GET', path: '/api/guest-pins' });
    assert.strictEqual(res.status, 401);
  });

  it('creates a guest PIN with the master PIN length', async () => {
    const res = await createGuestPin({ ttlMin: 60, maxUploads: 1, maxTotalBytesMB: 5 }, adminCookie);
    assert.strictEqual(res.status, 201);
    guestPin = { pin: res.json.pin, id: res.json.id };
    assert.strictEqual(guestPin.pin.length, 5, 'guest PIN must have the same length as the master PIN');
    assert.match(guestPin.pin, /^\d{5}$/);
  });

  it('lists the created guest PIN without exposing the hash', async () => {
    const res = await jsonRequest('GET', '/api/guest-pins', {}, adminCookie);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.enabled, true);
    const pin = res.json.pins.find(p => p.id === guestPin.id);
    assert.ok(pin, 'created PIN should be listed');
    assert.strictEqual(pin.pinHash, undefined, 'hash must never be exposed');
  });

  it('logs in a guest with name + PIN', async () => {
    const res = await jsonRequest('POST', '/api/auth/guest-verify', { name: 'Max', pin: guestPin.pin });
    assert.strictEqual(res.status, 200, `guest login failed: ${res.body}`);
    assert.strictEqual(res.json.success, true);
    const setCookie = res.headers['set-cookie'];
    assert.ok(setCookie, 'guest login should set a session cookie');
    cookieJar = setCookie.join('; ');
  });

  it('rejects a wrong guest PIN with a generic error', async () => {
    const res = await jsonRequest('POST', '/api/auth/guest-verify', { name: 'Max', pin: '99999' });
    assert.strictEqual(res.status, 401);
    assert.match(res.json.error, /expired|invalid/);
  });

  it('recognizes a guest PIN through the shared PIN field (verify-pin)', async () => {
    const res = await jsonRequest('POST', '/api/auth/verify-pin', { pin: guestPin.pin });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.success, true);
    assert.strictEqual(res.json.requiresName, true);
    assert.strictEqual(res.headers['set-cookie'], undefined, 'no session cookie before the name is provided');
  });

  it('completes a guest login through the shared PIN field', async () => {
    const created = await createGuestPin({ ttlMin: 60, maxUploads: 1, maxTotalBytesMB: 5 }, adminCookie);
    const verify = await jsonRequest('POST', '/api/auth/verify-pin', { pin: created.json.pin });
    assert.strictEqual(verify.json.requiresName, true);
    const res = await jsonRequest('POST', '/api/auth/guest-verify', { name: 'Alex', pin: created.json.pin });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.success, true);
    assert.ok(res.headers['set-cookie'], 'guest session cookie should be set');
  });

  it('rejects an expired guest PIN', async () => {
    const created = await createGuestPin({ ttlMin: 60, maxUploads: 1, maxTotalBytesMB: 5 }, adminCookie);
    await updateGuestPin(created.json.id, { expiresAt: Date.now() - 1000 });
    const res = await jsonRequest('POST', '/api/auth/guest-verify', { name: 'Zu', pin: created.json.pin });
    assert.strictEqual(res.status, 401);
    assert.match(res.json.error, /expired|invalid/);
  });

  it('uploads a file into the dedicated guest folder', async () => {
    const result = await guestUpload('photo.jpg', 'hello-world', cookieJar);
    assert.strictEqual(result.init.status, 200, `init failed: ${result.init.body}`);
    assert.strictEqual(result.chunk.status, 200, `chunk failed: ${result.chunk.body}`);

    // File must be inside uploads/guest/<name>_<id>_<YYYYMMDD>/
    const gastDir = path.join(UPLOAD_DIR, 'guest');
    assert.ok(fs.existsSync(gastDir), 'guest folder should exist');
    const folders = fs.readdirSync(gastDir);
    assert.strictEqual(folders.length, 1, 'exactly one guest folder expected');
    const folder = folders[0];
    assert.match(folder, new RegExp(`^Max_${guestPin.id}_\\d{8}$`));
    const filePath = path.join(gastDir, folder, 'photo.jpg');
    assert.ok(fs.existsSync(filePath), 'file should exist in guest folder');
    assert.strictEqual(fs.readFileSync(filePath, 'utf8'), 'hello-world');
  });

  it('records the upload in the guest PIN log', async () => {
    const res = await jsonRequest('GET', `/api/guest-pins/${guestPin.id}/uploads`, {}, adminCookie);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.json.uploads.length, 1);
    assert.strictEqual(res.json.uploads[0].filename, 'photo.jpg');
    assert.strictEqual(res.json.uploads[0].size, 11);
  });

  it('blocks further uploads once the PIN is used up', async () => {
    // PIN maxUploads=1 and one upload already recorded
    const initRes = await jsonRequest('POST', '/api/upload/init', { filename: 'x.txt', fileSize: 3 }, cookieJar);
    assert.strictEqual(initRes.status, 403);
    assert.match(initRes.json.error, /used up|invalid/);
  });

  it('stores the configured max uploads and allows exactly that many uploads', async () => {
    const created = await createGuestPin({ ttlMin: 60, maxUploads: 5, maxTotalBytesMB: 50 }, adminCookie);
    assert.strictEqual(created.json.maxUploads, 5, 'configured max uploads must be stored');

    const login = await jsonRequest('POST', '/api/auth/guest-verify', { name: 'Five', pin: created.json.pin });
    assert.strictEqual(login.status, 200);
    const fiveCookie = login.headers['set-cookie'].join('; ');

    for (let i = 0; i < 5; i++) {
      const res = await guestUpload(`file${i}.txt`, `content${i}`, fiveCookie);
      assert.strictEqual(res.init.status, 200, `upload ${i} should be allowed: ${res.init.body}`);
      assert.strictEqual(res.chunk.status, 200, `chunk ${i} should be allowed: ${res.chunk.body}`);
    }

    const sixth = await jsonRequest('POST', '/api/upload/init', { filename: 'sixth.txt', fileSize: 3 }, fiveCookie);
    assert.strictEqual(sixth.status, 403, 'sixth upload must be rejected');
  });

  it('permanently deletes a used-up guest PIN with purge', async () => {
    const created = await createGuestPin({ ttlMin: 60, maxUploads: 1, maxTotalBytesMB: 5 }, adminCookie);
    await updateGuestPin(created.json.id, { uploadCount: 1 }); // mark as used up

    const del = await makeRequest(
      { method: 'DELETE', path: `/api/guest-pins/${created.json.id}?purge=1`, headers: { Cookie: adminCookie } }
    );
    assert.strictEqual(del.status, 200, `purge failed: ${del.body}`);

    const list = await jsonRequest('GET', '/api/guest-pins', {}, adminCookie);
    assert.ok(!list.json.pins.find(p => p.id === created.json.id), 'deleted PIN must be gone');
  });

  it('rejects uploads exceeding the total quota', async () => {
    const created = await createGuestPin({ ttlMin: 60, maxUploads: 5, maxTotalBytesMB: 1 }, adminCookie);
    const login = await jsonRequest('POST', '/api/auth/guest-verify', { name: 'Quota', pin: created.json.pin });
    assert.strictEqual(login.status, 200);
    const quotaCookie = login.headers['set-cookie'].join('; ');

    const initRes = await jsonRequest('POST', '/api/upload/init', { filename: 'big.bin', fileSize: 2 * 1024 * 1024 }, quotaCookie);
    assert.strictEqual(initRes.status, 413, `expected quota rejection, got ${initRes.status}: ${initRes.body}`);
  });

  it('denies guests access to the file list', async () => {
    const res = await makeRequest({ method: 'GET', path: '/api/files', headers: { Cookie: cookieJar } });
    assert.strictEqual(res.status, 401);
  });

  it('denies guests access to guest PIN management', async () => {
    const res = await jsonRequest('GET', '/api/guest-pins', {}, cookieJar);
    assert.strictEqual(res.status, 401);
  });

  it('revokes a guest PIN and rejects its uploads', async () => {
    const created = await createGuestPin({ ttlMin: 60, maxUploads: 5, maxTotalBytesMB: 5 }, adminCookie);
    const del = await makeRequest(
      { method: 'DELETE', path: `/api/guest-pins/${created.json.id}`, headers: { Cookie: adminCookie } }
    );
    assert.strictEqual(del.status, 200);

    const login = await jsonRequest('POST', '/api/auth/guest-verify', { name: 'Rev', pin: created.json.pin });
    assert.strictEqual(login.status, 401, 'revoked PIN must not log in');
  });
});
