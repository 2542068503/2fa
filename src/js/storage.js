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
    const res = await fetch('/api/sync', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${adminSecret}`
      },
      cache: 'no-store'
    });

    if (res.status === 401) {
      return { data: null, timeOffsetMs: 0, error: 'UNAUTHORIZED_ADMIN' };
    }

    const dateHeader = res.headers.get('Date');
    let timeOffsetMs = 0;
    if (dateHeader) {
      const serverTime = new Date(dateHeader).getTime();
      timeOffsetMs = serverTime - Date.now();
    }

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
    const bodyPayload = { payload };

    const res = await fetch('/api/sync', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminSecret}`
      },
      body: JSON.stringify(bodyPayload)
    });
    return { success: res.status === 200, res };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// Tombstone logic removed for pure single-user cloud mode
