import { encryptVaultPayload, decryptVaultPayload } from './crypto.js';

const LOCAL_STORAGE_KEY = '2fa_vault_encrypted';

export function getStoredEncryptedVault() {
  const raw = localStorage.getItem(LOCAL_STORAGE_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (e) {
    return null;
  }
}

export function saveEncryptedVaultLocal(encryptedObj) {
  localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(encryptedObj));
}

export async function fetchCloudVault(kAuthHash) {
  try {
    const res = await fetch('/api/sync', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${kAuthHash}`
      },
      cache: 'no-store'
    });

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
    return { data: null, timeOffsetMs: 0 };
  }
}

export async function pushCloudVault(kAuthHash, encryptedObj) {
  try {
    const res = await fetch('/api/sync', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${kAuthHash}`
      },
      body: JSON.stringify({ payload: encryptedObj })
    });

    if (res.status === 409) {
      const json = await res.json();
      return { conflict: true, remotePayload: json.remotePayload };
    }
    return { success: res.status === 200 };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

export async function tombstoneCloudVault(kAuthHash) {
  try {
    // 1. Explicitly DELETE the old vault first
    await fetch('/api/sync', {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${kAuthHash}` }
    });

    // 2. Place a tombstone so other offline devices know it was revoked
    const res = await fetch('/api/sync', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${kAuthHash}`
      },
      body: JSON.stringify({ payload: { tombstone: true, updatedAt: Number.MAX_SAFE_INTEGER } })
    });
    
    return { success: res.status === 200 };
  } catch (err) {
    return { success: false, error: err.message };
  }
}
