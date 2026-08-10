import { initTheme, toggleTheme } from './theme.js';
import { deriveDeterministicSalts, deriveKeysWithWorker, encryptVaultPayload, decryptVaultPayload, base64ToBuffer, bufferToBase64 } from './crypto.js';
import { generateTOTP, getSecondsRemaining } from './totp.js';
import { getStoredEncryptedVault, saveEncryptedVaultLocal, fetchCloudVault, pushCloudVault } from './storage.js';
import { scanQrCodeFromImageFile, parseOtpauthUri } from './qr-parser.js';

let sessionState = {
  kEnc: null,
  kAuthHash: null,
  saltEncB64: '',
  saltAuthB64: '',
  vault: null,
  timeOffsetMs: 0,
  clipboardTimer: null,
  visibilityTimer: null,
  timerInterval: null
};

// DOM Elements
const lockView = document.getElementById('lockView');
const dashboardView = document.getElementById('dashboardView');
const masterPasswordInput = document.getElementById('masterPasswordInput');
const togglePwVisibility = document.getElementById('togglePwVisibility');
const unlockBtn = document.getElementById('unlockBtn');
const lockError = document.getElementById('lockError');
const lockBtn = document.getElementById('lockBtn');
const settingsBtn = document.getElementById('settingsBtn');
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
const toastText = document.getElementById('toastText');

// Settings Modal Elements
const settingsModal = document.getElementById('settingsModal');
const closeSettingsModalBtn = document.getElementById('closeSettingsModalBtn');
const cancelSettingsBtn = document.getElementById('cancelSettingsBtn');
const updatePasswordBtn = document.getElementById('updatePasswordBtn');
const currentPasswordInput = document.getElementById('currentPasswordInput');
const newPasswordInput = document.getElementById('newPasswordInput');
const confirmNewPasswordInput = document.getElementById('confirmNewPasswordInput');
const settingsError = document.getElementById('settingsError');

initTheme();
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

unlockBtn.addEventListener('click', handleUnlockOrCreate);
masterPasswordInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') handleUnlockOrCreate();
});

async function handleUnlockOrCreate() {
  const password = masterPasswordInput.value;
  if (!password) return;

  unlockBtn.querySelector('span').textContent = '同步解密中...';
  unlockBtn.disabled = true;
  lockError.style.display = 'none';

  try {
    const { saltEnc, saltAuth } = await deriveDeterministicSalts(password);
    const { kEnc, kAuthHash } = await deriveKeysWithWorker(password, saltEnc, saltAuth);

    sessionState.kEnc = kEnc;
    sessionState.kAuthHash = kAuthHash;
    sessionState.saltEncB64 = bufferToBase64(saltEnc);
    sessionState.saltAuthB64 = bufferToBase64(saltAuth);

    // Query Cloud KV with clean Hex kAuthHash
    const { data: cloudData, timeOffsetMs } = await fetchCloudVault(kAuthHash);
    sessionState.timeOffsetMs = timeOffsetMs;

    let decrypted = null;

    if (cloudData && cloudData.ciphertext) {
      try {
        decrypted = await decryptVaultPayload(cloudData.iv, cloudData.ciphertext, kEnc);
        saveEncryptedVaultLocal(cloudData);
      } catch (err) {
        // AES-GCM tag mismatch on cloud payload
      }
    }

    if (!decrypted) {
      const localEncrypted = getStoredEncryptedVault();
      if (localEncrypted && localEncrypted.ciphertext) {
        try {
          decrypted = await decryptVaultPayload(localEncrypted.iv, localEncrypted.ciphertext, kEnc);
        } catch (err) {
          // Stale local cache from previous algorithm version -> purge stale local storage
          localStorage.removeItem('2fa_vault_encrypted');
        }
      }
    }

    if (!decrypted) {
      // First time vault creation for this master password
      sessionState.vault = {
        magic: 'VALID_VAULT_V1',
        version: 1,
        updatedAt: Date.now(),
        accounts: []
      };
      await saveVault();
    } else {
      sessionState.vault = decrypted;
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
  settingsBtn.style.display = 'inline-flex';
  masterPasswordInput.value = '';
  renderAccountListStructure();
  updateTotpCodesInPlace();
  startTimerLoop();
}

async function saveVault() {
  sessionState.vault.updatedAt = Date.now();
  const encrypted = await encryptVaultPayload(sessionState.vault, sessionState.kEnc);

  const payload = {
    version: 1,
    saltEnc: sessionState.saltEncB64,
    saltAuth: sessionState.saltAuthB64,
    iv: encrypted.iv,
    ciphertext: encrypted.ciphertext,
    updatedAt: sessionState.vault.updatedAt
  };

  saveEncryptedVaultLocal(payload);
  const syncRes = await pushCloudVault(sessionState.kAuthHash, payload);

  if (syncRes && syncRes.conflict && syncRes.remotePayload) {
    // Merge conflict resolution
    try {
      const remoteDecrypted = await decryptVaultPayload(syncRes.remotePayload.iv, syncRes.remotePayload.ciphertext, sessionState.kEnc);
      const existingIds = new Set(sessionState.vault.accounts.map((a) => a.id));
      for (const rAcc of remoteDecrypted.accounts) {
        if (!existingIds.has(rAcc.id)) {
          sessionState.vault.accounts.push(rAcc);
        }
      }
      sessionState.vault.updatedAt = Date.now();
      const mergedEncrypted = await encryptVaultPayload(sessionState.vault, sessionState.kEnc);
      const mergedPayload = { ...payload, iv: mergedEncrypted.iv, ciphertext: mergedEncrypted.ciphertext, updatedAt: sessionState.vault.updatedAt };
      saveEncryptedVaultLocal(mergedPayload);
      await pushCloudVault(sessionState.kAuthHash, mergedPayload);
    } catch (e) {}
  }
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

// Build DOM structure ONLY when accounts list changes (prevents hover jittering)
function renderAccountListStructure() {
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

    const initial = (acc.issuer || 'U').substring(0, 1).toUpperCase();

    const card = document.createElement('div');
    card.className = `account-card-pro ${acc.pinned ? 'pinned' : ''}`;
    card.dataset.accId = acc.id;
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
        <div class="totp-code-display" title="点击复制">------</div>
        <div class="timer-ring-wrapper">
          <svg class="timer-ring-svg" viewBox="0 0 36 36">
            <circle class="timer-ring-bg" cx="18" cy="18" r="14"></circle>
            <circle class="timer-ring-circle" cx="18" cy="18" r="14"></circle>
          </svg>
          <span class="timer-ring-text">--</span>
        </div>
      </div>
    `;

    card.querySelector('.totp-code-display').addEventListener('click', (e) => {
      e.stopPropagation();
      const codeText = card.querySelector('.totp-code-display').dataset.rawCode;
      if (codeText) copyToClipboard(codeText);
    });

    card.addEventListener('click', () => {
      const codeText = card.querySelector('.totp-code-display').dataset.rawCode;
      if (codeText) copyToClipboard(codeText);
    });

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

// In-Place Update TOTP codes & timer rings every 1s without rebuilding DOM
async function updateTotpCodesInPlace() {
  if (!sessionState.vault) return;

  const cardElements = accountList.querySelectorAll('.account-card-pro');
  for (const card of cardElements) {
    const accId = card.dataset.accId;
    const acc = sessionState.vault.accounts.find((a) => a.id === accId);
    if (!acc) continue;

    const codeRaw = await generateTOTP(acc.secret, {
      algo: acc.algo || 'SHA1',
      digits: acc.digits || 6,
      period: acc.period || 30,
      timeOffsetMs: sessionState.timeOffsetMs
    });

    const formattedCode = formatTotpCode(codeRaw);
    const period = acc.period || 30;
    const rem = getSecondsRemaining(period, sessionState.timeOffsetMs);

    const codeDisplay = card.querySelector('.totp-code-display');
    const ringCircle = card.querySelector('.timer-ring-circle');
    const ringText = card.querySelector('.timer-ring-text');

    codeDisplay.textContent = formattedCode;
    codeDisplay.dataset.rawCode = codeRaw;
    ringText.textContent = rem;

    const strokeOffset = 88 * (1 - rem / period);
    ringCircle.style.strokeDashoffset = strokeOffset;

    if (rem <= 5) {
      ringCircle.classList.add('warning');
    } else {
      ringCircle.classList.remove('warning');
    }
  }
}

function showToast(msg) {
  toastText.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2200);
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text);
  showToast('验证码已复制到剪贴板！');

  if (sessionState.clipboardTimer) clearTimeout(sessionState.clipboardTimer);
  sessionState.clipboardTimer = setTimeout(() => {
    navigator.clipboard.writeText('');
  }, 30000);
}

function startTimerLoop() {
  if (sessionState.timerInterval) clearInterval(sessionState.timerInterval);
  sessionState.timerInterval = setInterval(updateTotpCodesInPlace, 1000);
}

// Lock
lockBtn.addEventListener('click', lockVault);

function lockVault() {
  sessionState.kEnc = null;
  sessionState.kAuthHash = null;
  sessionState.vault = null;
  if (sessionState.timerInterval) clearInterval(sessionState.timerInterval);
  dashboardView.style.display = 'none';
  lockView.style.display = 'block';
  lockBtn.style.display = 'none';
  settingsBtn.style.display = 'none';
}

// Settings Modal & Master Password Change Flow
settingsBtn.addEventListener('click', () => {
  currentPasswordInput.value = '';
  newPasswordInput.value = '';
  confirmNewPasswordInput.value = '';
  settingsError.style.display = 'none';
  settingsModal.classList.add('active');
});

closeSettingsModalBtn.addEventListener('click', () => settingsModal.classList.remove('active'));
cancelSettingsBtn.addEventListener('click', () => settingsModal.classList.remove('active'));

updatePasswordBtn.addEventListener('click', handleMasterPasswordChange);

async function handleMasterPasswordChange() {
  const currentPw = currentPasswordInput.value;
  const newPw = newPasswordInput.value;
  const confirmPw = confirmNewPasswordInput.value;

  if (!currentPw || !newPw || !confirmPw) {
    settingsError.textContent = '请完整填写所有密码项！';
    settingsError.style.display = 'block';
    return;
  }

  if (newPw !== confirmPw) {
    settingsError.textContent = '两次输入的新密码不一致！';
    settingsError.style.display = 'block';
    return;
  }

  if (newPw.length < 4) {
    settingsError.textContent = '新密码长度至少需要 4 位！';
    settingsError.style.display = 'block';
    return;
  }

  updatePasswordBtn.disabled = true;
  updatePasswordBtn.textContent = '密钥重新派生中...';
  settingsError.style.display = 'none';

  try {
    const { saltEnc: currentSaltEnc, saltAuth: currentSaltAuth } = await deriveDeterministicSalts(currentPw);
    const { kEnc: verifyKEnc } = await deriveKeysWithWorker(currentPw, currentSaltEnc, currentSaltAuth);
    
    // Verify current master password
    const localVault = getStoredEncryptedVault();
    if (localVault && localVault.ciphertext) {
      await decryptVaultPayload(localVault.iv, localVault.ciphertext, verifyKEnc);
    }

    // Re-encrypt vault under new master password
    const { saltEnc: newSaltEnc, saltAuth: newSaltAuth } = await deriveDeterministicSalts(newPw);
    const { kEnc: kEncNew, kAuthHash: kAuthHashNew } = await deriveKeysWithWorker(newPw, newSaltEnc, newSaltAuth);

    sessionState.kEnc = kEncNew;
    sessionState.kAuthHash = kAuthHashNew;
    sessionState.saltEncB64 = bufferToBase64(newSaltEnc);
    sessionState.saltAuthB64 = bufferToBase64(newSaltAuth);

    await saveVault();

    settingsModal.classList.remove('active');
    showToast('主密码修改成功！');
  } catch (err) {
    settingsError.textContent = err.message === 'INVALID_MAGIC' ? '当前主密码不正确！' : '修改失败: ' + err.message;
    settingsError.style.display = 'block';
  } finally {
    updatePasswordBtn.disabled = false;
    updatePasswordBtn.textContent = '确认更新密码';
  }
}

// Hotkeys: '/' focus search, 'Esc' lock or close modals
document.addEventListener('keydown', (e) => {
  if (e.key === '/' && document.activeElement !== searchInput && document.activeElement !== masterPasswordInput) {
    e.preventDefault();
    if (dashboardView.style.display !== 'none') searchInput.focus();
  }
  if (e.key === 'Escape') {
    if (addModal.classList.contains('active')) {
      addModal.classList.remove('active');
    } else if (settingsModal.classList.contains('active')) {
      settingsModal.classList.remove('active');
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
searchInput.addEventListener('input', () => {
  renderAccountListStructure();
  updateTotpCodesInPlace();
});

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

  saveAccountBtn.disabled = true;
  saveAccountBtn.textContent = '加密同步中...';

  try {
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
    renderAccountListStructure();
    updateTotpCodesInPlace();
    showToast('新 2FA 账号添加并同步成功！');
  } catch (err) {
    alert('保存账号失败: ' + err.message);
  } finally {
    saveAccountBtn.disabled = false;
    saveAccountBtn.textContent = '保存账号';
  }
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
    renderAccountListStructure();
    updateTotpCodesInPlace();
    showToast(`成功导入并同步 ${parsedAccounts.length} 个账号！`);
  } catch (err) {
    alert('二维码识别失败: ' + err.message);
  } finally {
    qrFileInput.value = '';
  }
});
