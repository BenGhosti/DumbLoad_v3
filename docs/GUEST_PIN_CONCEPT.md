# Concept: Guest PIN Upload Access

## Goal

The admin (logged in with the master PIN/passkey) creates random **guest PINs** from the upload page. A guest PIN:

- is **as long as the master PIN** (e.g. master PIN has 5 digits -> every guest PIN has 5 digits),
- has a **TTL** (configurable per PIN, default from `.env`),
- has a **max usage count** (1, 5, 10, ... - default from `.env`),
- has a **total size quota** (max bytes across all uploads of the PIN),
- expires after its TTL or when used up.

The guest:

1. opens the app URL,
2. enters his PIN in the **same PIN field** as the admin; the server recognizes a valid guest PIN and the UI asks for the guest's **name** (browser prompt),
3. can **only upload** (no file list, no downloads, no admin),
4. files land in `uploads/guest/<name>_<pinId>_<YYYYMMDD>/`,
5. sees a generic "PIN expired or invalid" message for invalid/expired PINs.

The admin sees the **Guest PINs** management (create, list, revoke, upload log) via a button in the top-left corner of the upload page (admin sessions only). No Apprise notifications for guests.

---

## 1. Configuration (`.env` / `src/config/index.js`)

| Variable | Description | Default |
| --- | --- | --- |
| `GUEST_PIN_ENABLED` | Feature on/off | `false` |
| `GUEST_PIN_TTL_DEFAULT` | Default TTL for new PINs (minutes) | `1440` (24h) |
| `GUEST_PIN_MAX_UPLOADS_DEFAULT` | Default upload count per PIN | `1` |
| `GUEST_PIN_MAX_TOTAL_MB_DEFAULT` | Default total quota in MB | `500` |
| `GUEST_PIN_PREFIX` | Folder name prefix | `guest` |
| `GUEST_SESSION_TIMEOUT` | Guest session lifetime (seconds) | `14400` (4h) |
| `CLAMAV_SCAN_ENABLED` | `off`, `guest`, or `all` | `off` |
| `CLAMAV_HOST` / `CLAMAV_PORT` | clamd address (TCP) | `127.0.0.1` / `3310` |
| `CLAMAV_TIMEOUT_MS` | Scan timeout | `30000` |
| `CLAMAV_FAIL_OPEN` | Accept upload when clamd is down (`true`) / reject (`false`) | `true` |
| `VIRUSTOTAL_ENABLED` | Extra VirusTotal engine (all uploads) | `false` |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key (required when enabled) | *(empty)* |
| `VIRUSTOTAL_UPLOAD_UNKNOWN` | Upload unknown-hash files (public in free tier!) | `false` |
| `VIRUSTOTAL_MAX_FILE_SIZE` | Upload limit in MB (free tier: 32); hash lookups work for any size | `32` |
| `VIRUSTOTAL_MIN_MALICIOUS_ENGINES` | Malicious engine count that counts as infected | `3` |

> **VirusTotal privacy note:** the default strategy sends **only the SHA-256
> hash** for a lookup - no file content ever leaves the server. Only with
> `VIRUSTOTAL_UPLOAD_UNKNOWN=true` are unknown files uploaded (public samples
> in the free tier). This is an explicit admin decision.

The feature is **optional**: without `GUEST_PIN_ENABLED=true` nothing changes.

---

## 2. Data model & persistence

New file: `src/utils/guestPins.js`

- Store: `guestPins.json` in the config dir (next to `.passkeys.json`), atomic writes (temp + rename).
- In-memory cache (load on start, write-through) + cleanup interval (remove unused expired PINs).

```json
{
  "id": "a1b2c3d4",
  "pinHash": "scrypt-salt:hash",
  "name": "max",
  "createdAt": 1785000000000,
  "expiresAt": 1785086400000,
  "maxUploads": 1,
  "uploadCount": 0,
  "maxTotalBytes": 524288000,
  "totalBytes": 0,
  "revoked": false,
  "lastUploadAt": null,
  "uploads": []
}
```

- PIN generation: `crypto.randomInt(0, 10)` per digit -> length = `config.pin.length`. Master and guest PINs are indistinguishable by construction.
- Hash: `crypto.scrypt` + random salt (no new dependency). Constant-time verification.
- Usage rules:
  - `uploadCount >= maxUploads` -> used up
  - `Date.now() > expiresAt` -> expired
  - `revoked` -> invalid immediately
  - `totalBytes + newFile > maxTotalBytes` -> upload rejected (413)

---

## 3. Auth flow

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `POST /api/auth/verify-pin` | public, rate-limited | checks master PIN; if not a match and a valid guest PIN is found, returns `{ success: true, requiresName: true }` |
| `POST /api/auth/guest-verify` | public, rate-limited | `{ name, pin }` -> re-validates the PIN, creates the guest session |
| `POST /api/guest-pins` | Admin session | create guest PIN (`ttlMin`, `maxUploads`, `maxTotalBytes`) -> returns the PIN **exactly once** |
| `GET /api/guest-pins` | Admin session | list all PINs (no hashes) with status + usage |
| `GET /api/guest-pins/:id/uploads` | Admin session | upload log of a PIN |
| `DELETE /api/guest-pins/:id` | Admin session | revoke a PIN immediately |

- `requireAuth()` carries the session: `{ role: 'admin' | 'guest', guestId }`.
  - Admin session: as before.
  - Guest session: only `/api/upload/**` (+ logout), never `/api/files/**`, admin UI, or passkey management -> `requireAuth({ allowGuest: true })` on upload routes, default rejects guests everywhere else.
- Generic error message for invalid/expired PINs (no distinction between "expired" and "wrong").
- Guest session TTL: `GUEST_SESSION_TIMEOUT` (short cookie, `httpOnly`, `SameSite=strict`).

---

## 4. Login UI (`public/login.html`)

- One single PIN field for both admin and guest.
- `verify-pin` first checks the master PIN; otherwise a guest PIN lookup runs.
- On `{ success: true, requiresName: true }` the UI asks via `window.prompt('Please enter your name:')` and completes the login through `guest-verify`.
- On error: toast/message "PIN expired or invalid".

---

## 5. Upload handling (`src/routes/upload.js`)

- Guest sessions in `/init`:
  - Target folder: `path.join(uploadDir, config.guestPinPrefix, '<sanitized_name>_<pinId>_<YYYYMMDD>')`,
  - `isPathWithinUploadDir()` checks stay active for all paths.
- Quota checks in `/init`:
  - PIN not active -> 403 "PIN used up or invalid",
  - `maxUploads` reached -> 403,
  - `totalBytes + size > maxTotalBytes` -> 413.
- Usage is booked only **after a successful, scan-approved, fully finished upload** (`recordGuestUpload`).
- `.partial` files and metadata stay in `uploadDir/.metadata`; the `uploadId` is random, guest folders prevent collisions.

---

## 6. Malware scanning (hybrid: ClamAV optional + VirusTotal hash-first)

### 6a. ClamAV (`src/services/clamav.js`, optional)

- No npm dependency: thin client against clamd over TCP using the `INSTREAM` protocol (`net.Socket`).
- Runs **synchronously** after finalization:
  1. stream the file to clamd,
  2. parse `OK` / `FOUND` / `ERROR`,
  3. `FOUND` -> delete the file, reject the upload ("File rejected (malware detected)"),
  4. clamd unreachable -> `CLAMAV_FAIL_OPEN` decides accept (warn) vs reject.
- Scope via `CLAMAV_SCAN_ENABLED`: `off` (default), `guest`, `all`.

### 6b. VirusTotal (`src/services/virustotal.js`)

- Optional extra engine for **all** uploads when `VIRUSTOTAL_ENABLED=true`.
- **Hash-first strategy (privacy-safe):**
  1. compute the local **SHA-256** hash (streamed),
  2. `GET /api/v3/files/<hash>` lookup - only the hash is sent,
  3. known hash -> instant verdict (`clean` / `infected`); infected files are deleted afterwards,
  4. unknown hash (404) -> marked **"not analyzed"**, unless `VIRUSTOTAL_UPLOAD_UNKNOWN=true` (then uploaded; that path is limited by `VIRUSTOTAL_MAX_FILE_SIZE` and rate limits).
- Free-tier rate limits (4 req/min): sliding-window queue; if no slot is available the scan is skipped, never blocking uploads.
- Verdicts update the guest upload log (`vt-ok`, `vt-found`, `vt-unknown`, `vt-skipped`, `vt-error`); infected uploads are deleted and the log entry removed.

### 6c. Interaction

| Situation | Behavior |
| --- | --- |
| ClamAV `FOUND` | Upload rejected, file deleted (VirusTotal is not even asked) |
| ClamAV `OK` or disabled, VT hash known | Upload confirmed; background verdict lands in the upload log |
| ClamAV `OK` or disabled, VT hash unknown, upload disabled | Upload confirmed, status "VT: not analyzed" |
| clamd down (`FAIL_OPEN=true`), VT active | Upload confirmed, VT is the only check |

---

## 7. Admin UI (upload page modal)

- Button top-left (like the theme toggle), visible only for `role: admin` sessions when the feature is enabled (server-side flag `{{GUEST_PIN_ADMIN}}`).
- Modal with:
  - **Create**: TTL, max uploads, max MB -> "Create Guest PIN". The response shows the **once-only PIN** with a copy button.
  - **List**: per PIN - status (active / expired / used up / revoked), created, expires, usage (`uploads x/y`, `size a/b`), guest name, last upload.
  - **Upload log**: per PIN expandable - file, size, time, scan status.
  - **Revoke**: sets `revoked: true`.
  - The list polls every 10s while the modal is open (acts as the in-app notification).
  - The once-only PIN display is hidden again when the modal is closed.
- The PIN management also used to live on the secret admin page; it is now only in the upload-page modal (admin page remains passkey management).

---

## 8. Security measures

- Guest PINs stored **only as scrypt hashes**; never shown again after creation.
- Same-length PINs + generic error message -> no external distinction between master/guest PINs.
- Rate limiting on `verify-pin`/`guest-verify` (brute force) and upload init (existing).
- RBAC: guest sessions can only reach `/api/upload/**` (never file list/downloads/admin).
- Quota + max uploads per PIN limit the blast radius.
- Path sanitization + `isPathWithinUploadDir` for all guest paths (incl. symlink escape).
- VirusTotal hash-only by default: no file content leaves the server for known files.

## 9. Deliberately NOT included (v1)

- Auto-delete/retention of guest files (decision: keep them forever).
- Apprise notifications for guests (admin UI replaces them).
- "Upload count" per multi-chunk file counts as 1 (booked after finalization).

## 10. Affected files

| File | Change |
| --- | --- |
| `src/config/index.js` | new env vars + validation |
| `src/utils/guestPins.js` | **new** - store, generation, verification, cleanup |
| `src/services/clamav.js` | **new** - clamd client (INSTREAM) |
| `src/services/virustotal.js` | **new** - hash-first VT client + optional upload fallback |
| `src/routes/auth.js` | `verify-pin` guest detection, `guest-verify`, status extension |
| `src/routes/guestPins.js` | **new** - admin CRUD + upload log |
| `src/utils/session.js` | `role`/`guestId` in sessions + guest TTL |
| `src/middleware/security.js` | `requireAuth({ allowGuest })`, guest restriction |
| `src/routes/upload.js` | guest folder, quota checks, scan hook, usage booking |
| `src/app.js` | routes, `{{GUEST_PIN_ADMIN}}` template flag |
| `public/login.html` | shared PIN field + name prompt |
| `public/index.html` | guest PIN management modal + top-left button |
| `public/admin.html` | reverted to passkey-only management |
| `test/` | guest auth, quota, expiry, scan rejection, path safety |
| `.env.example` / `README.md` | documentation |

## 11. Implementation order

1. Config + `guestPins.js` (store, generation, verification) + unit tests
2. Session/RBAC (`role`, `requireAuth({ allowGuest })`)
3. Auth: `verify-pin` guest detection + `guest-verify` + login UI
4. Upload: guest folder + quota + usage booking
5. ClamAV service + scan hook (`off`/`guest`/`all`)
6. VirusTotal hash-first service + background scan hook
7. Admin CRUD + upload-page modal + polling
8. Integration tests, `.env.example`, README
