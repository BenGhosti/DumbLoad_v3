# DumbLoad 🗂️

A stupid-simple, self-hosted file uploader. Drop files into a folder through a clean web interface — no cloud, no accounts, no nonsense. Your files go straight to your own server.

> Built with Node.js + vanilla JavaScript. No frontend build step, no client-side dependencies.

---

## ✨ Features

- 🖱️ **Drag & drop** files *and* folders (folder structure is preserved)
- 📋 **Clipboard paste** — hit `Ctrl+V` / `Cmd+V` to upload from the clipboard
- 📁 **Multiple file selection** with automatic deduplication
- ⚡ **Chunked uploads** with retry + resumable transfers (handles huge files)
- 🔐 **Authentication** — PIN, Passkey (WebAuthn), or **both** (PIN as fallback when you don't have your key)
- 🧭 **Passkey management** — add/remove security keys from a secret admin page
- ⏱️ **Configurable session timeout** — from 8 hours down to "instant"
- 🛡️ **Rate limiting** + brute-force protection with IP tracking
- 🎨 **Dark mode** + clean, responsive UI
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
- IP-based rate limiting + lockout (defends brute force, spoofing-safe)
- Path-traversal protection on all file operations
- Filename sanitization + extension filtering
- WebAuthn credential counter tracking (anti-replay)

---

## 📝 License

ISC — do whatever you want, just keep the copyright notice.
