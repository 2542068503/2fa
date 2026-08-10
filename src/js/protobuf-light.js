// Lightweight Protobuf decoder for otpauth-migration:// URIs (<10KB)
export function parseMigrationPayload(base64Data) {
  const binary = window.atob(base64Data);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  let index = 0;
  const accounts = [];

  while (index < bytes.length) {
    const key = readVarint(bytes, index);
    index = key.next;
    const fieldNum = key.val >> 3;
    const wireType = key.val & 0x07;

    if (fieldNum === 1 && wireType === 2) {
      // otp_parameters submessage
      const len = readVarint(bytes, index);
      index = len.next;
      const subEnd = index + len.val;
      const account = parseOtpParameters(bytes, index, subEnd);
      if (account.secret) {
        accounts.push(account);
      }
      index = subEnd;
    } else {
      index = skipField(bytes, index, wireType);
    }
  }

  return accounts;
}

function readVarint(bytes, start) {
  let res = 0;
  let shift = 0;
  let pos = start;
  while (pos < bytes.length) {
    const b = bytes[pos++];
    res |= (b & 0x7f) << shift;
    if ((b & 0x80) === 0) break;
    shift += 7;
  }
  return { val: res, next: pos };
}

function skipField(bytes, pos, wireType) {
  if (wireType === 0) {
    return readVarint(bytes, pos).next;
  } else if (wireType === 2) {
    const len = readVarint(bytes, pos);
    return len.next + len.val;
  }
  return pos + 1;
}

function parseOtpParameters(bytes, start, end) {
  let pos = start;
  let secretRaw = null;
  let name = '';
  let issuer = '';
  let algo = 'SHA1';
  let digits = 6;

  while (pos < end) {
    const key = readVarint(bytes, pos);
    pos = key.next;
    const fieldNum = key.val >> 3;
    const wireType = key.val & 0x07;

    if (fieldNum === 1 && wireType === 2) {
      // secret
      const len = readVarint(bytes, pos);
      pos = len.next;
      secretRaw = bytes.subarray(pos, pos + len.val);
      pos += len.val;
    } else if (fieldNum === 2 && wireType === 2) {
      // name
      const len = readVarint(bytes, pos);
      pos = len.next;
      name = new TextDecoder().decode(bytes.subarray(pos, pos + len.val));
      pos += len.val;
    } else if (fieldNum === 3 && wireType === 2) {
      // issuer
      const len = readVarint(bytes, pos);
      pos = len.next;
      issuer = new TextDecoder().decode(bytes.subarray(pos, pos + len.val));
      pos += len.val;
    } else if (fieldNum === 4 && wireType === 0) {
      // algorithm
      const val = readVarint(bytes, pos);
      pos = val.next;
      if (val.val === 2) algo = 'SHA256';
      if (val.val === 3) algo = 'SHA512';
    } else if (fieldNum === 5 && wireType === 0) {
      // digits
      const val = readVarint(bytes, pos);
      pos = val.next;
      digits = val.val === 2 ? 8 : 6;
    } else {
      pos = skipField(bytes, pos, wireType);
    }
  }

  // Convert raw secret to Base32 string
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let base32 = '';
  if (secretRaw) {
    let bits = 0;
    let value = 0;
    for (let i = 0; i < secretRaw.length; i++) {
      value = (value << 8) | secretRaw[i];
      bits += 8;
      while (bits >= 5) {
        base32 += alphabet[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) {
      base32 += alphabet[(value << (5 - bits)) & 31];
    }
  }

  return { secret: base32, account: name, issuer, algo, digits, period: 30 };
}
