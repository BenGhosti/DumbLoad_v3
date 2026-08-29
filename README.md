# DumbLoad 🗂️

A stupid-simple, self-hosted file uploader. Drop files into a folder through a clean web interface — no cloud, no accounts, no nonsense. Your files go straight to your own server.

> Built with Node.js + vanilla JavaScript. No frontend build step, no client-side dependencies.

---

## ✨ Features

- 🖱️ **Drag & drop** files *and* folders (folder structure is preserved)
- 📋 **Clipboard paste** — hit `Ctrl+V` / `Cmd+V` on desktop, or just **tap the drop zone on mobile** to paste text *or images* from the clipboard
- 📁 **Multiple file selection** with automatic deduplication
- ⚡ **Chunked uploads** with retry + resumable transfers (handles huge files)
- 🔐 **Authentication** — PIN, Passkey (WebAuthn), or **both** (PIN as fallback when you don't have your key)
- 🧭 **Passkey management** — add/remove security keys from a secret admin page
- 🎟️ **Guest PIN access (optional)** — create time-limited, usage-limited upload PINs from the admin page; guests can upload without an account
- 🦠 **Malware scanning (optional)** — ClamAV (local) and/or VirusTotal (background) scanning of uploads
- ⏱️ **Configurable session timeout** — from 8 hours down to "instant"
- 🛡️ **Rate limiting** + brute-force protection with IP tracking
- 🎨 **Dark mode** + responsive **mobile view** with touch-friendly controls
- 📋 **Optional file listing** — download, rename, and delete from the browser
- 🎯 **File extension filtering** and **max file size** limits
- 🔔 **Notifications** via Apprise (any supported service)
- 📦 **Docker + Unraid** friendly — ships with compose defaults

---

## 🚀 Quick Start (Docker Compose)

```bash
git clone <your-repo-url>
cd DumbLoad_v3
cp .env.example .env
# edit .env: set BASE_URL, DUMBLOAD_PIN, DUMBLOAD_AUTH_MODE, etc.
docker compose up -d
```

Then open `http://<your-server>:3800`.

The repo's `docker-compose.yml` ships with **Unraid-friendly defaults**:

```yaml
services:
  dumbload:
    build: .                 # built locally (no registry pull)
    container_name: dumbload
    restart: unless-stopped
    ports:
      - "3800:3000"          # external : internal
    volumes:
      - ${APP_DATA_PATH:-/mnt/user/appdata/dumbload}:/app/config     # passkeys/config
      - ${FILES_PATH:-/mnt/user/appdata/dumbload-files}:/app/uploads # your files
    env_file:
      - .env
    environment:
      UPLOAD_DIR: /app/uploads
      DUMBLOAD_CONFIG_DIR: /app/config
```

| Compose path variable | Purpose                          | Default                              |
| --------------------- | -------------------------------- | ------------------------------------ |
| `APP_DATA_PATH`       | App config (passkeys)            | `/mnt/user/appdata/dumbload`         |
| `FILES_PATH`          | Uploaded/downloaded files        | `/mnt/user/appdata/dumbload-files`   |

---

## 🔐 Authentication

DumbLoad supports three login modes via `DUMBLOAD_AUTH_MODE`:

| Mode       | Behavior                                                              |
| ---------- | --------------------------------------------------------------------- |
| `pin`      | Only PIN login                                                        |
| `passkey`  | Only Passkey/WebAuthn login                                           |
| `both`     | **PIN or Passkey** — either works (recommended)                       |

### Setting up Passkeys

1. Set `DUMBLOAD_ADMIN_PATH` to a secret path (e.g. `/admin-8f3k2`).
2. Set `DUMBLOAD_AUTH_MODE=both` (or `passkey`).
3. Visit the secret admin path once (you'll need your PIN to get in) and register your security keys (YubiKey, Windows Hello, phone, …).

> **Important:** Passkeys only work in browsers over **HTTPS** with a hostname, or on **localhost**. A plain `http://IP:port` or a single-label hostname is rejected by the browser. Use a reverse proxy (see below) for production.

---

## ⚙️ Configuration

All settings live in the `.env` file. Copy `.env.example` to get started.

### Server

| Variable            | Description                                     | Default               |
| ------------------- | ----------------------------------------------- | --------------------- |
| `PORT`              | Internal container port                         | `3000`                |
| `BASE_URL`          | Public URL you use to access the app            | `http://localhost:3000/` |
| `NODE_ENV`          | `production` or `development`                   | `production`          |

### Uploads

| Variable             | Description                                    | Default             |
| -------------------- | ---------------------------------------------- | ------------------- |
| `MAX_FILE_SIZE`      | Max file size in MB                            | `1024`              |
| `ALLOWED_EXTENSIONS` | Comma-separated allowed extensions (empty = all) | *(all)*           |
| `AUTO_UPLOAD`        | Upload immediately on selection (`true`/`false`) | `false`           |
| `SHOW_FILE_LIST`     | Enable file listing (download/rename/delete)   | `false`             |
| `UPLOAD_DIR`         | Upload dir (Docker: set automatically)         | *(auto)*            |
| `DUMBLOAD_CONFIG_DIR`| App config dir (passkeys)                      | upload dir          |

### Security & Authentication

| Variable             | Description                                                        | Default          |
| -------------------- | ------------------------------------------------------------------ | ---------------- |
| `DUMBLOAD_PIN`       | PIN (4–10 digits, empty = no PIN)                                  | *(none)*         |
| `DUMBLOAD_AUTH_MODE` | `pin`, `passkey`, or `both`                                        | `both`           |
| `SESSION_TIMEOUT`    | Session timeout in seconds (`instant`/`0` = browser-session only)  | `28800` (8h)     |
| `DUMBLOAD_RP_ID`     | WebAuthn Relying Party ID override                                 | hostname of BASE_URL |
| `DUMBLOAD_RP_NAME`   | WebAuthn Relying Party name                                        | `DumbLoad`       |
| `DUMBLOAD_ADMIN_PATH`| Secret path for passkey management (empty = admin **disabled**)    | *(disabled)*     |
| `TRUST_PROXY`        | Trust proxy headers (`X-Forwarded-*`) — enable behind a reverse proxy | `false`      |
| `TRUSTED_PROXY_IPS`  | Comma-separated trusted proxy IPs (requires `TRUST_PROXY=true`)    | *(none)*         |

### Guest PIN access

| Variable                    | Description                                                        | Default          |
| --------------------------- | ------------------------------------------------------------------ | ---------------- |
| `GUEST_PIN_ENABLED`         | Enable guest upload PINs (requires `DUMBLOAD_PIN`)                 | `false`          |
| `GUEST_PIN_TTL_DEFAULT`     | Default TTL for new guest PINs (minutes)                           | `1440` (24h)     |
| `GUEST_PIN_MAX_UPLOADS_DEFAULT` | Default max uploads per PIN (0 = unlimited)                    | `1`              |
| `GUEST_PIN_MAX_TOTAL_MB_DEFAULT`| Default total size quota per PIN in MB (0 = unlimited)         | `500`            |
| `GUEST_PIN_PREFIX`          | Folder prefix for guest uploads                                    | `guest`          |
| `GUEST_SESSION_TIMEOUT`     | Guest session lifetime (seconds)                                   | `14400` (4h)     |

### Malware scanning

| Variable                        | Description                                                        | Default         |
| ------------------------------- | ------------------------------------------------------------------ | --------------- |
| `CLAMAV_SCAN_ENABLED`           | `off`, `guest` (only guest uploads), or `all` (every upload)       | `off`           |
| `CLAMAV_HOST` / `CLAMAV_PORT`   | clamd address                                                      | `127.0.0.1`/`3310` |
| `CLAMAV_TIMEOUT_MS`             | Scan timeout                                                       | `30000`         |
| `CLAMAV_FAIL_OPEN`              | Accept upload when clamd is down (`true`) or reject (`false`)      | `true`          |
| `VIRUSTOTAL_ENABLED`            | Extra VirusTotal scan (background, all uploads)                    | `false`         |
| `VIRUSTOTAL_API_KEY`            | Comma-separated API keys; next key is used automatically when one hits its rate limit | *(none)* |
| `VIRUSTOTAL_MAX_FILE_SIZE`      | Max file size for VT scans in MB (free tier: 32)                   | `32`            |
| `VIRUSTOTAL_MIN_MALICIOUS_ENGINES` | Malicious engine count that counts as infected                  | `3`             |

| `VIRUSTOTAL_UPLOAD_UNKNOWN` | Upload unknown-hash files for analysis (see warning)              | `false`          |

> **VirusTotal privacy note:** by default only the file's **SHA-256 hash** is
> sent for a lookup — no file content ever leaves your server. Only if
> `VIRUSTOTAL_UPLOAD_UNKNOWN=true` are unknown files uploaded for analysis; in
> the free tier those samples are **public**.

### Notifications

| Variable            | Description                                    | Default                                           |
| ------------------- | ---------------------------------------------- | ------------------------------------------------- |
| `APPRISE_URL`       | Apprise URL (empty = notifications disabled)   | *(none)*                                          |
| `APPRISE_MESSAGE`   | Message template with `{filename}`, `{size}`, `{storage}` | `New file uploaded {filename} ({size}), Storage used {storage}` |
| `APPRISE_SIZE_UNIT` | `B`, `KB`, `MB`, `GB`, `TB`, or `Auto`         | `Auto`                                            |

### CORS / Embedding

| Variable            | Description                                    | Default             |
| ------------------- | ---------------------------------------------- | ------------------- |
| `ALLOWED_ORIGINS`   | Comma-separated allowed CORS origins           | `*`                 |
| `ALLOWED_IFRAME_ORIGINS` | *(deprecated — use `ALLOWED_ORIGINS`)*     | *(none)*            |

---

## 🎟️ Guest PIN access (optional)

Give people temporary upload access without handing out the master PIN:

1. Set `GUEST_PIN_ENABLED=true` (and `DUMBLOAD_PIN`).
2. Log in as admin and open the main page's **guest PIN** button (top-left) or the secret admin page.
3. Create a PIN (choose TTL, max uploads, total quota). The PIN is shown **exactly once** — copy it and share it.
4. Guests open your URL, enter **their name + the guest PIN**, and can only upload. Files land in `uploads/guest/<name>_<pinId>_<YYYYMMDD>/`.
5. The admin page lists every PIN with status, usage, quota, and a per-PIN upload log (with scan results) — no Apprise needed for guests.

Guest PINs:
- are as long as the master PIN (they cannot be distinguished from outside),
- are stored only as scrypt hashes,
- expire after their TTL or once `maxUploads`/the total quota is used up,
- can be revoked immediately.

---

## 🦠 Malware scanning (optional)

- **ClamAV** (`CLAMAV_SCAN_ENABLED=guest|all`) scans synchronously; infected files are deleted and the upload is rejected. `CLAMAV_FAIL_OPEN` decides what happens if clamd is unreachable.
- **VirusTotal** (`VIRUSTOTAL_ENABLED=true`) runs as an extra engine in the background and never blocks uploads. It first computes the local **SHA-256 hash** and looks it up on VirusTotal — no file content leaves the server. Unknown hashes are marked *not analyzed* unless `VIRUSTOTAL_UPLOAD_UNKNOWN=true` (then they are uploaded; only that upload path is limited by `VIRUSTOTAL_MAX_FILE_SIZE` and the rate limit). If a verdict comes back infected, the file is deleted afterwards.

---

## 🔁 Reverse Proxy (HTTPS)

DumbLoad itself speaks **plain HTTP** on port `3000` (exposed as `3800`). For HTTPS + Passkeys, put a reverse proxy in front of it and set:

```env
BASE_URL=https://drop.your-domain.de/
TRUST_PROXY=true
```

> **Nginx Proxy Manager example:** keep the upstream **Scheme = `http`** (the proxy talks HTTP to the backend), forward to `192.168.x.x:3800`, and enable an SSL certificate on the public side. DumbLoad then auto-detects the `https` origin.

---

## 🛡️ Security

- Constant-time PIN comparison
- Session tokens (HTTP-only, `SameSite=strict` cookies) with configurable timeout
- Role separation: guest sessions can only upload, never list/download/delete files or reach the admin
- Guest PINs stored as scrypt hashes only (never readable again after creation)
- IP-based rate limiting + lockout (defends brute force, spoofing-safe)
- Path-traversal protection on all file operations
- Filename sanitization + extension filtering
- WebAuthn credential counter tracking (anti-replay)

---

## License

Copyright (c) 2026 BenGhosti. All rights reserved.


Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files, to use and distribute the software in its original, unmodified form, subject to the following conditions:


1. **Attribution:** The above copyright notice and this permission notice must be included in all copies or substantial portions of the Software.
2. **Non-Commercial Use:** The software may only be used and distributed for non-commercial purposes. Commercial use of any kind is strictly prohibited.
3. **No Publication of Modifications:** You may modify the software for your own personal use. However, you are strictly prohibited from publishing, distributing, or sharing any modified versions of the software.


THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY.
