// Base32 Decoder
export function parseBase32(base32) {
  if (!base32) return new Uint8Array(8);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let cleaned = base32.replace(/[\s=-]/g, '').toUpperCase();
  let bits = '';

  for (let i = 0; i < cleaned.length; i++) {
    const val = alphabet.indexOf(cleaned[i]);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }

  if (bits.length === 0) return new Uint8Array(8);

  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(bits.substr(i * 8, 8), 2);
  }
  return bytes.length > 0 ? bytes : new Uint8Array(8);
}

// Steam 5-character Base Alphabet Mapping
const STEAM_ALPHABET = '2345678bcdefghjkmnpqrstvwxyz';

export async function generateTOTP(secretBase32, options = {}) {
  const {
    algo = 'SHA1',
    digits = 6,
    period = 30,
    timeOffsetMs = 0,
    timestamp = Date.now()
  } = options;

  const effectiveTime = timestamp + timeOffsetMs;
  const counter = Math.floor(effectiveTime / 1000 / period);

  // Convert counter to 8-byte big-endian ArrayBuffer
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setBigUint64(0, BigInt(counter), false);

  const secretBytes = parseBase32(secretBase32);

  // Select HMAC Algorithm Name
  let hashName = 'SHA-1';
  if (algo === 'SHA256') hashName = 'SHA-256';
  if (algo === 'SHA512') hashName = 'SHA-512';

  const cryptoKey = await window.crypto.subtle.importKey(
    'raw',
    secretBytes,
    { name: 'HMAC', hash: { name: hashName } },
    false,
    ['sign']
  );

  const hmacSig = await window.crypto.subtle.sign('HMAC', cryptoKey, buffer);
  const hmacBytes = new Uint8Array(hmacSig);

  // Dynamic Truncation
  const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
  const binary =
    ((hmacBytes[offset] & 0x7f) << 24) |
    ((hmacBytes[offset + 1] & 0xff) << 16) |
    ((hmacBytes[offset + 2] & 0xff) << 8) |
    (hmacBytes[offset + 3] & 0xff);

  // Handle STEAM Guard 5-character custom mapping
  if (algo === 'STEAM') {
    let code = '';
    let fullCode = binary;
    for (let i = 0; i < 5; i++) {
      code += STEAM_ALPHABET[fullCode % STEAM_ALPHABET.length];
      fullCode = Math.floor(fullCode / STEAM_ALPHABET.length);
    }
    return code.toUpperCase();
  }

  // Standard numeric TOTP
  const modulus = Math.pow(10, digits);
  const codeNum = binary % modulus;
  return codeNum.toString().padStart(digits, '0');
}

export function getSecondsRemaining(period = 30, timeOffsetMs = 0) {
  const effectiveTime = Date.now() + timeOffsetMs;
  const secondsInPeriod = Math.floor(effectiveTime / 1000) % period;
  return period - secondsInPeriod;
}
