/**
 * ClamAV tests.
 * Unit tests for the clamd INSTREAM client plus an integration test of the
 * guest upload scan pipeline against a fake clamd server.
 */

// Disable batch cleanup for tests
process.env.DISABLE_BATCH_CLEANUP = 'true';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

// Temp upload dir must exist and be set BEFORE requiring the app
const UPLOAD_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'dumbload-clamav-test-'));

// Feature + scan config must be set BEFORE requiring the app
process.env.DUMBLOAD_PIN = '1234';
process.env.GUEST_PIN_ENABLED = 'true';
process.env.CLAMAV_SCAN_ENABLED = 'guest';
process.env.CLAMAV_HOST = '127.0.0.1';
process.env.CLAMAV_PORT = '33999';
process.env.CLAMAV_FAIL_OPEN = 'true';
process.env.LOCAL_UPLOAD_DIR = UPLOAD_DIR;

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const net = require('node:net');

const { app, initialize } = require('../src/app');
const { runClamavScan, scanFile } = require('../src/services/clamav');
const { pinVerifyLimiter } = require('../src/middleware/rateLimiter');

// NOTE: we deliberately do NOT write the real EICAR string to disk here -
// Windows Defender would lock the file (EPERM) while scanning it.
const INFECTED_MARKER = 'MALWARE-TEST-MARKER';
const INFECTED_CONTENT = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$' + INFECTED_MARKER + '!$H+H*';

/**
 * Fake clamd: reads INSTREAM chunks and replies based on file content.
 */
function startFakeClamd() {
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    let received = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      received = Buffer.concat([received, chunk]);
      // INSTREAM: a 4-byte zero length chunk marks the end
      if (received.length >= 4) {
        const tail = received.subarray(received.length - 4);
        if (tail.equals(Buffer.alloc(4))) {
          const infected = received.includes(Buffer.from(INFECTED_MARKER));
          socket.write(infected ? 'stream: Eicar-Test-Signature FOUND\0' : 'stream: OK\0');
          socket.end();
        }
      }
    });
    socket.on('error', () => {});
    socket.on('close', () => sockets.delete(socket));
  });
  server.listen(Number(process.env.CLAMAV_PORT), '127.0.0.1');
  return server;
}

let server;
let adminCookie;
let guestCookie;

before(async () => {
  await initialize();
  server = http.createServer(app);
  await new Promise((resolve) => {
    server.listen(0, () => resolve());
  });

  // Admin login + create guest PIN + guest login
  const adminRes = await request('POST', '/api/auth/verify-pin', JSON.stringify({ pin: '1234' }), 'application/json');
  adminCookie = adminRes.headers['set-cookie'].join('; ');

  const createRes = await request('POST', '/api/guest-pins', JSON.stringify({ ttlMin: 60, maxUploads: 10, maxTotalBytesMB: 5 }), 'application/json', adminCookie);
  const pin = JSON.parse(createRes.body).pin;

  const guestRes = await request('POST', '/api/auth/guest-verify', JSON.stringify({ name: 'Scan', pin }), 'application/json');
  guestCookie = guestRes.headers['set-cookie'].join('; ');
});

after(async () => {
  if (server) await new Promise((resolve) => server.close(resolve));
  fs.rmSync(UPLOAD_DIR, { recursive: true, force: true });
});

function request(method, route, body, contentType = '', cookie = '') {
  return new Promise((resolve, reject) => {
    const headers = {};
    if (contentType) headers['Content-Type'] = contentType;
    if (cookie) headers.Cookie = cookie;
    const req = http.request({ host: '127.0.0.1', port: server.address().port, method, path: route, headers }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

async function upload(content, filename = 'scan.txt') {
  const init = await request('POST', '/api/upload/init', JSON.stringify({ filename, fileSize: Buffer.byteLength(content) }), 'application/json', guestCookie);
  if (init.status !== 200) return { status: init.status, body: init.body };
  const uploadId = JSON.parse(init.body).uploadId;
  const chunk = await request('POST', `/api/upload/chunk/${uploadId}`, content, 'application/octet-stream', guestCookie);
  return { status: chunk.status, body: chunk.body };
}

function guestFolders() {
  const gastDir = path.join(UPLOAD_DIR, 'guest');
  if (!fs.existsSync(gastDir)) return [];
  return fs.readdirSync(gastDir);
}

describe('ClamAV scan service (fake clamd)', () => {
  let fakeClamd;

  before(() => {
    fakeClamd = startFakeClamd();
    try { pinVerifyLimiter.resetKey('127.0.0.1'); } catch { /* ignore */ }
  });

  after(() => {
    if (fakeClamd) fakeClamd.close();
  });

  it('flags an infected file as found', async () => {
    const tmpFile = path.join(UPLOAD_DIR, 'infected.txt');
    fs.writeFileSync(tmpFile, INFECTED_CONTENT);
    const result = await runClamavScan(tmpFile);
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.status, 'clamav-found');
    assert.match(result.signature || '', /Eicar/i);
  });

  it('accepts a clean file', async () => {
    const tmpFile = path.join(UPLOAD_DIR, 'clean.txt');
    fs.writeFileSync(tmpFile, 'just some clean text');
    const result = await runClamavScan(tmpFile);
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.status, 'clamav-ok');
  });

  it('reports an error when clamd is unreachable', async () => {
    const tmpFile = path.join(UPLOAD_DIR, 'down.txt');
    fs.writeFileSync(tmpFile, 'content');
    const result = await scanFile(tmpFile, { host: '127.0.0.1', port: 1, timeoutMs: 500 });
    assert.strictEqual(result.status, 'error');
  });

  it('accepts a clean guest upload (scan ok)', async () => {
    const result = await upload('clean guest file content');
    assert.strictEqual(result.status, 200, `upload failed: ${result.body}`);
    assert.ok(guestFolders().length >= 1, 'guest folder should exist');
  });

  it('rejects an infected guest upload and deletes the file', async () => {
    const beforeDirs = guestFolders();
    const result = await upload(INFECTED_CONTENT, 'evil.txt');
    assert.strictEqual(result.status, 400, `infected upload must be rejected, got ${result.status}: ${result.body}`);
    assert.match(result.body, /malware|rejected/i);

    const afterDirs = guestFolders();
    assert.strictEqual(afterDirs.length, beforeDirs.length, 'no new folder expected for rejected upload');
    for (const folder of afterDirs) {
      const files = fs.readdirSync(path.join(UPLOAD_DIR, 'guest', folder));
      assert.ok(!files.includes('evil.txt'), 'infected file must be deleted');
    }
  });

  it('does not record rejected uploads in the guest log', async () => {
    const listRes = await request('GET', '/api/guest-pins', '', '', adminCookie);
    const pins = JSON.parse(listRes.body).pins;
    const scanPin = pins.find(p => p.name === 'Scan');
    assert.ok(scanPin);
    const evilEntries = scanPin.uploads.filter(u => u.filename === 'evil.txt');
    assert.strictEqual(evilEntries.length, 0, 'rejected upload must not consume quota/log entry');
  });
});
