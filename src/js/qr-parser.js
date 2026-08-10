import jsQR from 'jsqr';
import { parseMigrationPayload } from './protobuf-light.js';

export function parseOtpauthUri(uriStr) {
  if (uriStr.startsWith('otpauth-migration://')) {
    const url = new URL(uriStr);
    const data = url.searchParams.get('data');
    if (data) {
      return parseMigrationPayload(data);
    }
    throw new Error('Invalid migration URI');
  }

  if (!uriStr.startsWith('otpauth://')) {
    throw new Error('Invalid OTP Auth URI format');
  }

  const url = new URL(uriStr);
  const type = url.host; // totp
  const pathLabel = decodeURIComponent(url.pathname.substring(1));
  let issuer = url.searchParams.get('issuer') || '';
  let account = pathLabel;

  if (pathLabel.includes(':')) {
    const parts = pathLabel.split(':');
    if (!issuer) issuer = parts[0].trim();
    account = parts[1].trim();
  }

  const secret = url.searchParams.get('secret') || '';
  const algo = (url.searchParams.get('algorithm') || 'SHA1').toUpperCase();
  const digits = parseInt(url.searchParams.get('digits') || '6', 10);
  const period = parseInt(url.searchParams.get('period') || '30', 10);

  return [
    {
      issuer: issuer || 'Unknown',
      account: account || 'Account',
      secret,
      algo,
      digits,
      period
    }
  ];
}

export function scanQrCodeFromImageFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        canvas.width = img.width;
        canvas.height = img.height;
        ctx.drawImage(img, 0, 0);

        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imageData.data, imageData.width, imageData.height);

        if (code && code.data) {
          resolve(code.data);
        } else {
          reject(new Error('No QR code detected in image'));
        }
      };
      img.onerror = () => reject(new Error('Failed to load image'));
      img.src = e.target.result;
    };
    reader.onerror = () => reject(new Error('Failed to read file'));
    reader.readAsDataURL(file);
  });
}
