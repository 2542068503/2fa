// Helper for ArrayBuffer / Uint8Array zeroing
export function zeroBuffer(uint8Array) {
  if (uint8Array && uint8Array.fill) {
    uint8Array.fill(0);
  }
}

// Convert Uint8Array to Base64 and back
export function bufferToBase64(buf) {
  let binary = '';
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

export function base64ToBuffer(b64) {
  const binary = window.atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function generateSalt(length = 16) {
  return window.crypto.getRandomValues(new Uint8Array(length));
}

// Derive keys using Web Worker
export async function deriveKeysWithWorker(password, saltEnc, saltAuth) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./crypto-worker.js', import.meta.url), { type: 'module' });

    worker.onmessage = async (e) => {
      if (e.data.type === 'DERIVE_SUCCESS') {
        const { kEncBits, kAuthBits } = e.data;

        // Import AES-GCM Key
        const kEnc = await window.crypto.subtle.importKey(
          'raw',
          kEncBits,
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt']
        );

        const kAuthHash = bufferToBase64(kAuthBits);

        // Zero out worker raw bit copies
        zeroBuffer(kEncBits);
        zeroBuffer(kAuthBits);
        worker.terminate();

        resolve({ kEnc, kAuthHash });
      } else if (e.data.type === 'DERIVE_ERROR') {
        worker.terminate();
        reject(new Error(e.data.error));
      }
    };

    worker.postMessage({
      type: 'DERIVE_KEYS',
      password,
      saltEnc,
      saltAuth
    });
  });
}

// Encrypt payload object
export async function encryptVaultPayload(payloadObj, kEnc) {
  const enc = new TextEncoder();
  const plaintextBytes = enc.encode(JSON.stringify(payloadObj));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const ciphertextBuf = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    kEnc,
    plaintextBytes
  );

  return {
    iv: bufferToBase64(iv),
    ciphertext: bufferToBase64(ciphertextBuf)
  };
}

// Decrypt payload object
export async function decryptVaultPayload(ivB64, ciphertextB64, kEnc) {
  const iv = base64ToBuffer(ivB64);
  const ciphertext = base64ToBuffer(ciphertextB64);

  const decryptedBuf = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    kEnc,
    ciphertext
  );

  const dec = new TextDecoder();
  const jsonStr = dec.decode(decryptedBuf);
  const parsed = JSON.parse(jsonStr);

  if (parsed.magic !== 'VALID_VAULT_V1') {
    throw new Error('INVALID_MAGIC');
  }

  return parsed;
}
