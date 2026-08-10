# 2FA Web Authenticator

A modern, zero-trust, end-to-end encrypted (E2EE) 2FA (TOTP) web application with serverless cloud synchronization.

## Features
- **Zero-Trust & E2EE**: AES-256-GCM encryption with 600,000 PBKDF2 iterations computed in a Web Worker.
- **Serverless Cloud Sync**: Free deployment on Cloudflare Pages / Vercel with KV optimistic concurrency control.
- **Multi-Algorithm Support**: Standard RFC 6238 (SHA1, SHA256, SHA512) and Steam Guard 5-character tokens.
- **Offline PWA**: Full offline calculation support with Web App Manifest and Service Worker.
- **Light & Dark Theme**: Sleek glassmorphism visual design with system theme detection.
- **QR Code Scanning**: Import accounts directly from QR code images or Google Authenticator migration URIs.

## Cloudflare Pages Deployment
1. Push repository to GitHub/GitLab.
2. Go to Cloudflare Dashboard -> **Workers & Pages** -> **Create Application** -> **Pages**.
3. Connect your git repository.
4. Set Build command: `npm run build`
5. Set Build output directory: `dist`
6. Create a Cloudflare KV namespace named `VAULT_KV` and bind it to your Pages project under **Settings** -> **Functions** -> **KV Namespace Bindings**.

## Local Development
```bash
npm install
npm run dev
```
