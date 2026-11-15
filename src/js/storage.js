import { encryptVaultPayload, decryptVaultPayload } from './crypto.js';

const LOCAL_STORAGE_KEY = '2fa_vault_encrypted';

export function getStoredEncryptedVault() {
  return null; // Local caching completely disabled for pure cloud mode
}

export function saveEncryptedVaultLocal(payload) {
  // Local caching completely disabled for pure cloud mode
}

export async function fetchCloudVault(adminSecret) {
  try {
    const tStart = Date.now();
    const res = await fetch('/api/sync', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${adminSecret}`,
        'Cache-Control': 'no-cache'
      },
      cache: 'no-store'
    });
    const tEnd = Date.now();
    const rtt = Math.max(0, tEnd - tStart);

    if (res.status === 401) {
      return { data: null, timeOffsetMs: 0, error: 'UNAUTHORIZED_ADMIN' };
    }

    if (res.status === 500) {
      try {
        const errJson = await res.json();
        if (errJson && errJson.error === 'MISSING_ENV_ADMIN') {
          return { data: null, timeOffsetMs: 0, error: 'MISSING_ENV_ADMIN' };
        }
      } catch (_) {}
    }

    // Default to 0ms (Local device clock) to ensure 100% exact parity with 2fa.fun, Google Authenticator, etc.
    let timeOffsetMs = 0;

    if (res.status === 200) {
      const json = await res.json();
      return { data: json.data, timeOffsetMs };
    }
    return { data: null, timeOffsetMs };
  } catch (err) {
    return { data: null, timeOffsetMs: 0, error: err.message };
  }
}

export async function pushCloudVault(payload, adminSecret) {
  try {
    const tStart = Date.now();
    const bodyPayload = { payload };

    const res = await fetch('/api/sync', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminSecret}`,
        'Cache-Control': 'no-cache'
      },
      cache: 'no-store',
      body: JSON.stringify(bodyPayload)
    });
    const tEnd = Date.now();
    const rtt = Math.max(0, tEnd - tStart);

    return { success: res.status === 200, res, timeOffsetMs: 0 };
  } catch (err) {
    return { success: false, error: err.message, timeOffsetMs: null };
  }
}

// Tombstone logic removed for pure single-user cloud mode
