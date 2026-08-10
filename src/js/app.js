import { initTheme, toggleTheme } from './theme.js';
import { deriveKeysWithWorker, encryptVaultPayload, decryptVaultPayload, base64ToBuffer, bufferToBase64 } from './crypto.js';
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
const togglePwVisibility = document.getElementById('togglePwVisibility');
const unlockBtn = document.getElementById('unlockBtn');
const lockError = document.getElementById('lockError');
const lockBtn = document.getElementById('lockBtn');
const themeToggleBtn = document.getElementById('themeToggleBtn');
const accountList = document.getElementById('accountList');
const searchInput = document.getElementById('searchInput');
const addAccountBtn = document.getElementById('addAccountBtn');
const addModal = document.getElementById('addModal');
const closeAddModalBtn = document.getElementById('closeAddModalBtn');
const cancelAddBtn = document.getElementById('cancelAddBtn');
const saveAccountBtn = document.getElementById('saveAccountBtn');
const qrFileInput = document.getElementById('qrFileInput');
const toast = document.getElementById('toast');

initTheme();
checkExistingVaultStatus();
setupServiceWorker();

// Theme Switcher
themeToggleBtn.addEventListener('click', () => {
  toggleTheme();
});

function setupServiceWorker() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  }
}

// Password Visibility Toggle
togglePwVisibility.addEventListener('click', () => {
  const isPw = masterPasswordInput.type === 'password';
  masterPasswordInput.type = isPw ? 'text' : 'password';
});

function checkExistingVaultStatus() {
  const localVault = getStoredEncryptedVault();
  if (!localVault) {
    document.getElementById('lockTitle').textContent = '创建主密码库';
    document.getElementById('lockDesc').textContent = '第一次使用？请设置主密码（Master Password）来加密保护您的验证码。';
    unlockBtn.querySelector('span').textContent = '创建密码库';
  }
}

unlockBtn.addEventListener('click', handleUnlockOrCreate);
masterPasswordInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') handleUnlockOrCreate();
});

async function handleUnlockOrCreate() {
  const password = masterPasswordInput.value;
  if (!password) return;

  unlockBtn.querySelector('span').textContent = '解密计算中...';
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
    lockError.textContent = err.message === 'INVALID_MAGIC' ? '密码不正确！请重新输入' : '密码库解密失败！';
    lockError.style.display = 'block';
  } finally {
    unlockBtn.querySelector('span').textContent = '解锁验证器';
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

function formatTotpCode(code) {
  if (code.length === 6) {
    return `${code.slice(0, 3)} ${code.slice(3)}`;
  }
  if (code.length === 8) {
    return `${code.slice(0, 4)} ${code.slice(4)}`;
  }
  return code;
}

async function renderAccounts() {
  if (!sessionState.vault) return;
  accountList.innerHTML = '';
  const filter = searchInput.value.toLowerCase().trim();

  const sortedAccounts = [...sessionState.vault.accounts].sort((a, b) => (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0));

  let count = 0;
  for (const acc of sortedAccounts) {
    if (filter && !acc.issuer.toLowerCase().includes(filter) && !acc.account.toLowerCase().includes(filter)) {
      continue;
    }
    count++;

    const codeRaw = await generateTOTP(acc.secret, {
      algo: acc.algo || 'SHA1',
      digits: acc.digits || 6,
      period: acc.period || 30,
      timeOffsetMs: sessionState.timeOffsetMs
    });

    const formattedCode = formatTotpCode(codeRaw);
    const period = acc.period || 30;
    const rem = getSecondsRemaining(period, sessionState.timeOffsetMs);

    // Calculate stroke dashoffset for 36px ring (radius 14, circumference ~88)
    const strokeOffset = 88 * (1 - rem / period);
    const isWarning = rem <= 5;

    const initial = (acc.issuer || 'U').substring(0, 1).toUpperCase();

    const card = document.createElement('div');
    card.className = `account-card-pro ${acc.pinned ? 'pinned' : ''}`;
    card.innerHTML = `
      <div class="account-info">
        <div class="service-avatar">${initial}</div>
        <div class="account-details">
          <div class="issuer-name">
            ${acc.issuer}
            ${acc.pinned ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="var(--accent)" stroke="none"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>' : ''}
          </div>
          <div class="account-handle">${acc.account}</div>
        </div>
      </div>
      <div class="totp-section">
        <div class="totp-code-display" title="点击复制">${formattedCode}</div>
        <div class="timer-ring-wrapper">
          <svg class="timer-ring-svg" viewBox="0 0 36 36">
            <circle class="timer-ring-bg" cx="18" cy="18" r="14"></circle>
            <circle class="timer-ring-circle ${isWarning ? 'warning' : ''}" cx="18" cy="18" r="14" style="stroke-dashoffset: ${strokeOffset}"></circle>
          </svg>
          <span class="timer-ring-text">${rem}</span>
        </div>
      </div>
    `;

    card.querySelector('.totp-code-display').addEventListener('click', (e) => {
      e.stopPropagation();
      copyToClipboard(codeRaw);
    });

    card.addEventListener('click', () => copyToClipboard(codeRaw));
    accountList.appendChild(card);
  }

  if (count === 0) {
    accountList.innerHTML = `
      <div class="empty-state">
        <svg class="empty-state-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
        </svg>
        <h3 style="font-size: 1.1rem; margin-bottom: 0.5rem; color: var(--text-primary);">未找到 2FA 验证账号</h3>
        <p style="font-size: 0.9rem;">点击上方“+ 添加账号”或“📷 扫码识别”来开始导入您的动态验证码。</p>
      </div>
    `;
  }
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text);
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2200);

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
cancelAddBtn.addEventListener('click', () => addModal.classList.remove('active'));

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
    alert(`成功导入 ${parsedAccounts.length} 个 2FA 验证账号！`);
  } catch (err) {
    alert('二维码识别失败: ' + err.message);
  } finally {
    qrFileInput.value = '';
  }
});
