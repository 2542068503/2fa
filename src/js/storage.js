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

    let timeOffsetMs = 0;
    const dateHeader = res.headers.get('Date');
    if (dateHeader) {
      const serverTime = new Date(dateHeader).getTime();
      if (!isNaN(serverTime)) {
        // HTTP Date has 1-second resolution; add 500ms as expected midpoint.
        // Server generated response at approximately tStart + (rtt / 2).
        const serverEstimatedNow = serverTime + 500;
        const clientMidpoint = tStart + (rtt / 2);
        const calculatedOffset = serverEstimatedNow - clientMidpoint;

        // TUN / Proxy safeguard:
        // 1. If RTT is excessively large (> 3500ms), network jitter is too unstable; trust local clock.
        // 2. If calculated offset is within +/- 2500ms, the local system clock is already accurate enough for TOTP (30s window).
        //    Applying a noisy offset from HTTP headers would do more harm than good.
        if (rtt <= 3500 && Math.abs(calculatedOffset) >= 2500) {
          timeOffsetMs = Math.round(calculatedOffset);
          console.info(`[TimeSync] Applied clock calibration offset: ${timeOffsetMs}ms (RTT: ${rtt}ms)`);
        } else {
          console.info(`[TimeSync] Clock in sync or RTT too high (Offset: ${Math.round(calculatedOffset)}ms, RTT: ${rtt}ms), using local clock.`);
        }
      }
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

    let timeOffsetMs = null;
    const dateHeader = res.headers.get('Date');
    if (dateHeader) {
      const serverTime = new Date(dateHeader).getTime();
      if (!isNaN(serverTime)) {
        const serverEstimatedNow = serverTime + 500;
        const clientMidpoint = tStart + (rtt / 2);
        const calculatedOffset = serverEstimatedNow - clientMidpoint;
        if (rtt <= 3500 && Math.abs(calculatedOffset) >= 2500) {
          timeOffsetMs = Math.round(calculatedOffset);
        } else if (rtt <= 3500) {
          timeOffsetMs = 0;
        }
      }
    }

    return { success: res.status === 200, res, timeOffsetMs };
  } catch (err) {
    return { success: false, error: err.message, timeOffsetMs: null };
  }
}

// Tombstone logic removed for pure single-user cloud mode
