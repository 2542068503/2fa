# 2FA / TOTP Web Authenticator Design Specification

## 1. Overview
A modern, zero-trust, end-to-end encrypted (E2EE) 2FA (TOTP) web authenticator application with serverless cross-device cloud synchronization. Hostable for free on Cloudflare Pages / Vercel with PWA offline-first support, strict master-password protection, Web Worker PBKDF2 offloading, responsive light/dark theme modes, and custom TOTP algorithm configuration (including Steam Guard 5-character tokens).

---

## 2. Security & Cryptography Architecture

### 2.1 Key Derivation & Encryption
- **PBKDF2 Offloaded to Web Worker**: **600,000 iterations** using `PBKDF2-HMAC-SHA256` offloaded to a dedicated Web Worker (`crypto-worker.js`) to keep the UI at 60 FPS during unlock operations.
- **Master Encryption Key (`K_enc`)**: Derived from Master Password and `Salt_enc`. Used exclusively client-side to encrypt/decrypt vault payload with `AES-256-GCM`.
- **API Authentication Token (`K_auth`)**: Derived from Master Password and `Salt_auth` via separate PBKDF2 (`10,000` iterations) to produce a hashed Bearer Token. Sent as `Authorization: Bearer <K_auth_hash>` to authorize `/api/sync` endpoint without exposing `K_enc` or plain text secrets to Cloudflare/Vercel.

### 2.2 Vault Structure & Verification Marker
Plaintext Vault Payload before encryption:
```json
{
  "magic": "VALID_VAULT_V1",
  "version": 1,
  "updatedAt": 1700000000000,
  "accounts": [
    {
      "id": "uuid-v4",
      "issuer": "GitHub",
      "account": "user@example.com",
      "secret": "JBSWY3DPEHPK3PXP",
      "algo": "SHA1",
      "digits": 6,
      "period": 30,
      "pinned": true,
      "createdAt": 1700000000000,
      "updatedAt": 1700000000000
    }
  ]
}
```
* **Verification Marker**: Verification checks `magic === "VALID_VAULT_V1"`. If AES-GCM fails or `magic` is missing, UI cleanly distinguishes between **Incorrect Password** vs **Corrupted Data**.

### 2.3 Memory Safety & Clipboard Auto-Clear
- **Memory Zeroing**: Upon manual lock, visibility auto-lock, or inactivity timeout, sensitive `Uint8Array` / `ArrayBuffer` objects containing secrets or derived key material are explicitly zero-filled (`buffer.fill(0)`) before dereferencing.
- **Tab Visibility Auto-Lock**: Monitors `document.visibilitychange`. If the browser tab remains hidden for over 60 seconds, auto-locks the vault and zeros memory.
- **Clipboard Auto-Clear**: Clicking a 2FA code copies it to the clipboard and schedules a 30-second timer to erase the clipboard if it still matches the copied TOTP code.

### 2.4 Master Password Change Flow
1. User enters current password and new password in settings.
2. App decrypts current vault payload into memory.
3. Generates new `Salt_enc_new` and `Salt_auth_new`.
4. Derives `K_enc_new` and `K_auth_new` via Web Worker.
5. Re-encrypts payload with `K_enc_new`.
6. Sends POST to `/api/sync` with new `K_auth_new` header and payload, updating both KV and `localStorage`.

---

## 3. Storage, Cloud Sync & Conflict Resolution

### 3.1 Encrypted Payload Format (KV / LocalStorage)
```json
{
  "version": 1,
  "saltEnc": "Base64_Encoded_Salt_Enc",
  "saltAuth": "Base64_Encoded_Salt_Auth",
  "iv": "Base64_Encoded_IV",
  "ciphertext": "Base64_Encoded_Ciphertext",
  "updatedAt": 1700000000000
}
```

### 3.2 Cloud Sync, OCC & Rate Limiting
- **Endpoint**: `/api/sync` (Cloudflare Pages Function / Vercel API).
- **Authentication**: Checked against `K_auth_hash` Bearer Header. Rate limited to 30 requests/minute per IP.
- **Clock Drift Calibration**: Reads the HTTP `Date` header from API responses to calculate `Time Offset = Server Time - Client Time`. The offset is injected into TOTP counter calculations to eliminate code rejection caused by unsynchronized device clocks.
- **Cloudflare KV OCC & Conflict Resolution**:
  - GET `/api/sync`: Returns encrypted payload and HTTP `Date` header.
  - POST `/api/sync`: Compares client `updatedAt` vs KV stored `updatedAt`. If server timestamp is higher, returns `409 Conflict`.
  - Conflict Resolution Modal: Allows user to choose "Keep Cloud Version", "Keep Local Version", or perform account-level merge.

---

## 4. TOTP Compatibility (Standard & Steam Guard)

### 4.1 Custom TOTP Parameters Support
- **Digits**: 6-digit (standard), 8-digit (Steam/AWS/Banks).
- **Period**: 30 seconds (standard), 60 seconds.
- **Algorithm**:
  - `SHA1` (standard)
  - `SHA256`
  - `SHA512`
  - `STEAM` (Steam Guard 5-character alphabet mapping: `2345678bcdefghjkmnpqrstvwxyz`).

### 4.2 Import & Export Formats
- **Export**: Encrypted Vault Backup (`.2favault` JSON) and Plaintext `otpauth://` URI list.
- **Import**: Manual Base32 secret entry, QR image scanner, `otpauth://` URI list, and Google Authenticator `otpauth-migration://` URI decoding via lightweight standalone Protobuf Varint decoder (<20KB).
- **Emergency Backup Prompt**: Mandatory prompt during initial vault creation encouraging user to save an emergency plaintext backup file.

---

## 5. Offline-First PWA Support
- **Service Worker (`sw.js`)**: Caches static shell assets (HTML, CSS, JS, icons) for 100% offline availability.
- **Web App Manifest (`manifest.json`)**: Configures stand-alone PWA mode with app icon, splash colors, and home-screen installability.
- **Offline Sync Fallback**: Offline changes save to LocalStorage and auto-sync to Cloudflare KV when network connection is restored.

---

## 6. UI / UX Design & Theme System

### 6.1 Theme & Design Aesthetics
- **Modes**: Light & Dark mode with CSS Variables system (`data-theme="light"` / `data-theme="dark"`).
- **Visual Style**: Modern slate palette, glassmorphism card containers, crisp typography, responsive layout for mobile and desktop.
- **Theme Switcher**: Header toggle button (☀️ / 🌙) with system preference auto-detection.

### 6.2 Key Features & Components
1. **Lock Screen**:
   - Master Password input, password visibility toggle, Unlock button with loading indicator.
   - Status indicators (New Vault setup mode vs Existing Vault unlock mode).
2. **Dashboard Toolbar**:
   - Live Search bar (Hotkey: `/` or `Ctrl+F` to focus).
   - Filter by Pinned / All accounts.
   - Action buttons: Add (`+`), Scan QR, Import/Export, Settings, Theme Toggle, Lock (`Esc`).
3. **Account Cards**:
   - Brand Icon resolution (GitHub, Google, Microsoft, AWS, Binance, Steam, etc., with fallback generic avatar).
   - Account Issuer & Name label.
   - Pin / Star toggle.
   - Large formatted TOTP display (`123 456`, `1234 5678`, or `2V3B4` for Steam).
   - Animated SVG 30s/60s countdown progress ring (incorporating server clock drift offset).
   - Copy action with toast feedback.
4. **Modals**:
   - Add/Edit Account Modal (supports QR image drop/upload).
   - Cloud Sync Status / Conflict Resolution Modal.
   - Import/Export & Change Master Password Settings Modal.

---

## 7. Project File Structure
```
2fa/
├── functions/
│   └── api/
│       └── sync.js          # Cloudflare KV Sync API with K_auth Bearer check & Rate limit
├── public/
│   ├── favicon.svg
│   ├── icon-192.png
│   ├── icon-512.png
│   ├── manifest.json        # PWA Manifest
│   └── sw.js                # Service Worker for offline shell caching
├── src/
│   ├── assets/
│   │   └── icons/           # Service Brand SVGs (GitHub, Google, AWS, Steam, etc.)
│   ├── css/
│   │   └── style.css        # Complete CSS token system (Light/Dark mode)
│   ├── js/
│   │   ├── crypto-worker.js # Web Worker for 600k PBKDF2 key derivation & zeroing
│   │   ├── crypto.js        # Web Worker wrapper & Web Crypto AES-GCM helpers
│   │   ├── totp.js          # RFC 6238 TOTP (SHA1/256/512, STEAM, 6/8 digits, clock drift)
│   │   ├── protobuf-light.js# Lightweight protobuf parser for otpauth-migration
│   │   ├── qr-parser.js     # QR code image parsing wrapper
│   │   ├── storage.js       # Encrypted LocalStorage & API sync manager with OCC
│   │   ├── theme.js         # Theme toggle & system detection
│   │   └── app.js           # UI logic, hotkeys, search, clipboard timer, zeroing, visibility lock
│   └── index.html
├── package.json
├── vite.config.js
└── README.md                # Cloudflare Pages / Vercel deployment guide
```
