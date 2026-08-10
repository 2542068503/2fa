import { initTheme, toggleTheme } from './theme.js';
import { deriveKeysWithWorker, encryptVaultPayload, decryptVaultPayload, zeroBuffer, bufferToBase64, base64ToBuffer } from './crypto.js';
import { generateTOTP, getSecondsRemaining } from './totp.js';
import { getStoredEncryptedVault, saveEncryptedVaultLocal, fetchCloudVault, pushCloudVault } from './storage.js';
import { scanQrCodeFromImageFile, parseOtpauthUri } from './qr-parser.js';

let sessionState = {
  kEnc: null,
  kAuthHash: null,
  vault: null,
  timeOffsetMs: 0,
  clipboardTimer: null,
  visibilityTimer: null
};

// DOM Elements
const lockView = document.getElementById('lockView');
const dashboardView = document.getElementById('dashboardView');
const masterPasswordInput = document.getElementById('masterPasswordInput');
const unlockBtn = document.getElementById('unlockBtn');
const lockError = document.getElementById('lockError');
const lockBtn = document.getElementById('lockBtn');
const themeToggleBtn = document.getElementById('themeToggleBtn');
const accountList = document.getElementById('accountList');
const searchInput = document.getElementById('searchInput');
const addAccountBtn = document.getElementById('addAccountBtn');
const addModal = document.getElementById('addModal');
const closeAddModalBtn = document.getElementById('closeAddModalBtn');
const saveAccountBtn = document.getElementById('saveAccountBtn');
const qrFileInput = document.getElementById('qrFileInput');
const toast = document.getElementById('toast');

initTheme();
checkExistingVaultStatus();
setupServiceWorker();

themeToggleBtn.addEventListener('click', () => {
  themeToggleBtn.textContent = toggleTheme() === 'dark' ? '☀️' : '🌙';
});

function setupServiceWorker() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  }
}

function checkExistingVaultStatus() {
  const localVault = getStoredEncryptedVault();
  if (!localVault) {
    document.getElementById('lockTitle').textContent = 'Create New Vault';
    document.getElementById('lockDesc').textContent = 'Set a master password to encrypt your 2FA accounts.';
    unlockBtn.textContent = 'Create Vault';
  }
}

unlockBtn.addEventListener('click', handleUnlockOrCreate);
masterPasswordInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') handleUnlockOrCreate();
});

async function handleUnlockOrCreate() {
  const password = masterPasswordInput.value;
  if (!password) return;

  unlockBtn.textContent = 'Decrypting...';
  unlockBtn.disabled = true;
  lockError.style.display = 'none';

  try {
    let localEncrypted = getStoredEncryptedVault();
    let saltEnc, saltAuth;

    if (!localEncrypted) {
      saltEnc = window.crypto.getRandomValues(new Uint8Array(16));
      saltAuth = window.crypto.getRandomValues(new Uint8Array(16));
    } else {
      saltEnc = base64ToBuffer(localEncrypted.saltEnc);
      saltAuth = base64ToBuffer(localEncrypted.saltAuth);
    }

    const { kEnc, kAuthHash } = await deriveKeysWithWorker(password, saltEnc, saltAuth);
    sessionState.kEnc = kEnc;
    sessionState.kAuthHash = kAuthHash;

    if (!localEncrypted) {
      sessionState.vault = {
        magic: 'VALID_VAULT_V1',
        version: 1,
        updatedAt: Date.now(),
        accounts: []
      };
      await saveVault(bufferToBase64(saltEnc), bufferToBase64(saltAuth));
    } else {
      const parsed = await decryptVaultPayload(localEncrypted.iv, localEncrypted.ciphertext, kEnc);
      sessionState.vault = parsed;

      // Sync cloud in background
      const { data, timeOffsetMs } = await fetchCloudVault(kAuthHash);
      sessionState.timeOffsetMs = timeOffsetMs;
      if (data && data.updatedAt > sessionState.vault.updatedAt) {
        sessionState.vault = await decryptVaultPayload(data.iv, data.ciphertext, kEnc);
        saveEncryptedVaultLocal(data);
      }
    }

    showDashboard();
  } catch (err) {
    lockError.textContent = err.message === 'INVALID_MAGIC' ? 'Incorrect Password!' : 'Decryption Failed!';
    lockError.style.display = 'block';
  } finally {
    unlockBtn.textContent = 'Unlock Vault';
    unlockBtn.disabled = false;
  }
}

function showDashboard() {
  lockView.style.display = 'none';
  dashboardView.style.display = 'block';
  lockBtn.style.display = 'inline-flex';
  masterPasswordInput.value = '';
  renderAccounts();
  startTimerLoop();
}

async function saveVault(saltEncB64, saltAuthB64) {
  sessionState.vault.updatedAt = Date.now();
  const encrypted = await encryptVaultPayload(sessionState.vault, sessionState.kEnc);

  const localVault = getStoredEncryptedVault();
  const payload = {
    version: 1,
    saltEnc: saltEncB64 || (localVault ? localVault.saltEnc : ''),
    saltAuth: saltAuthB64 || (localVault ? localVault.saltAuth : ''),
    iv: encrypted.iv,
    ciphertext: encrypted.ciphertext,
    updatedAt: sessionState.vault.updatedAt
  };

  saveEncryptedVaultLocal(payload);
  await pushCloudVault(sessionState.kAuthHash, payload);
}

async function renderAccounts() {
  if (!sessionState.vault) return;
  accountList.innerHTML = '';
  const filter = searchInput.value.toLowerCase();

  if (sessionState.vault.accounts.length === 0) {
    accountList.innerHTML = '<div style="text-align: center; color: var(--text-secondary); padding: 2rem;">No 2FA accounts added yet. Click "+ Add" or "📷 Scan QR" to start.</div>';
    return;
  }

  for (const acc of sessionState.vault.accounts) {
    if (filter && !acc.issuer.toLowerCase().includes(filter) && !acc.account.toLowerCase().includes(filter)) {
      continue;
    }

    const code = await generateTOTP(acc.secret, {
      algo: acc.algo || 'SHA1',
      digits: acc.digits || 6,
      period: acc.period || 30,
      timeOffsetMs: sessionState.timeOffsetMs
    });

    const rem = getSecondsRemaining(acc.period || 30, sessionState.timeOffsetMs);

    const card = document.createElement('div');
    card.className = 'account-card';
    card.innerHTML = `
      <div>
        <div style="font-weight: 600; font-size: 1.1rem;">${acc.issuer}</div>
        <div style="color: var(--text-secondary); font-size: 0.875rem;">${acc.account}</div>
      </div>
      <div style="display: flex; align-items: center; gap: 1rem;">
        <div class="code-display">${code}</div>
        <div style="font-size: 0.85rem; font-weight: 600; color: var(--text-secondary); min-width: 28px; text-align: right;">${rem}s</div>
      </div>
    `;

    card.addEventListener('click', () => copyToClipboard(code));
    accountList.appendChild(card);
  }
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text);
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2000);

  if (sessionState.clipboardTimer) clearTimeout(sessionState.clipboardTimer);
  sessionState.clipboardTimer = setTimeout(() => {
    navigator.clipboard.writeText('');
  }, 30000);
}

function startTimerLoop() {
  setInterval(renderAccounts, 1000);
}

// Lock
lockBtn.addEventListener('click', lockVault);

function lockVault() {
  sessionState.kEnc = null;
  sessionState.kAuthHash = null;
  sessionState.vault = null;
  dashboardView.style.display = 'none';
  lockView.style.display = 'block';
  lockBtn.style.display = 'none';
}

// Hotkeys: '/' focus search, 'Esc' lock
document.addEventListener('keydown', (e) => {
  if (e.key === '/' && document.activeElement !== searchInput && document.activeElement !== masterPasswordInput) {
    e.preventDefault();
    if (dashboardView.style.display !== 'none') searchInput.focus();
  }
  if (e.key === 'Escape') {
    if (addModal.classList.contains('active')) {
      addModal.classList.remove('active');
    } else if (sessionState.vault) {
      lockVault();
    }
  }
});

// Auto lock on tab hidden over 60s
document.addEventListener('visibilitychange', () => {
  if (document.hidden && sessionState.vault) {
    sessionState.visibilityTimer = setTimeout(() => {
      lockVault();
    }, 60000);
  } else if (!document.hidden && sessionState.visibilityTimer) {
    clearTimeout(sessionState.visibilityTimer);
  }
});

// Search input
searchInput.addEventListener('input', renderAccounts);

// Add modal
addAccountBtn.addEventListener('click', () => addModal.classList.add('active'));
closeAddModalBtn.addEventListener('click', () => addModal.classList.remove('active'));

saveAccountBtn.addEventListener('click', async () => {
  const issuer = document.getElementById('addIssuerInput').value || 'Unknown';
  const account = document.getElementById('addAccountInput').value || 'Account';
  const secret = document.getElementById('addSecretInput').value;
  const algo = document.getElementById('addAlgoSelect').value || 'SHA1';

  if (!secret) return;

  sessionState.vault.accounts.push({
    id: window.crypto.randomUUID(),
    issuer,
    account,
    secret,
    algo,
    digits: algo === 'STEAM' ? 5 : 6,
    period: 30,
    createdAt: Date.now()
  });

  await saveVault();
  addModal.classList.remove('active');
  document.getElementById('addIssuerInput').value = '';
  document.getElementById('addAccountInput').value = '';
  document.getElementById('addSecretInput').value = '';
  renderAccounts();
});

// QR File Scanner
qrFileInput.addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;

  try {
    const qrData = await scanQrCodeFromImageFile(file);
    const parsedAccounts = parseOtpauthUri(qrData);

    for (const acc of parsedAccounts) {
      sessionState.vault.accounts.push({
        id: window.crypto.randomUUID(),
        issuer: acc.issuer,
        account: acc.account,
        secret: acc.secret,
        algo: acc.algo || 'SHA1',
        digits: acc.digits || 6,
        period: acc.period || 30,
        createdAt: Date.now()
      });
    }

    await saveVault();
    renderAccounts();
    alert(`Successfully imported ${parsedAccounts.length} 2FA account(s)!`);
  } catch (err) {
    alert('QR Code Scan Failed: ' + err.message);
  } finally {
    qrFileInput.value = '';
  }
});
