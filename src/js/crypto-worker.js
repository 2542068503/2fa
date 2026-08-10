// Web Worker for PBKDF2 600k key derivation & zeroing
self.onmessage = async (e) => {
  const { type, password, saltEnc, saltAuth } = e.data;
  if (type === 'DERIVE_KEYS') {
    try {
      const enc = new TextEncoder();
      const pwBytes = enc.encode(password);

      const baseKey = await self.crypto.subtle.importKey(
        'raw',
        pwBytes,
        { name: 'PBKDF2' },
        false,
        ['deriveBits', 'deriveKey']
      );

      // K_enc: 600,000 iterations for vault encryption
      const kEncBits = await self.crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          salt: saltEnc,
          iterations: 600000,
          hash: 'SHA-256'
        },
        baseKey,
        256
      );

      // K_auth: 10,000 iterations for API authentication token
      const kAuthBits = await self.crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          salt: saltAuth,
          iterations: 10000,
          hash: 'SHA-256'
        },
        baseKey,
        256
      );

      // Zero out password bytes
      pwBytes.fill(0);

      self.postMessage({
        type: 'DERIVE_SUCCESS',
        kEncBits: new Uint8Array(kEncBits),
        kAuthBits: new Uint8Array(kAuthBits)
      });
    } catch (err) {
      self.postMessage({ type: 'DERIVE_ERROR', error: err.message });
    }
  }
};
