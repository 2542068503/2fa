import { initTheme, toggleTheme } from './theme.js';
import { deriveDeterministicSalts, deriveKeysWithWorker, encryptVaultPayload, decryptVaultPayload, base64ToBuffer, bufferToBase64 } from './crypto.js';
import { generateTOTP, getSecondsRemaining } from './totp.js';
import { fetchCloudVault, pushCloudVault } from './storage.js';
import { scanQrCodeFromImageFile, parseOtpauthUri } from './qr-parser.js';

let sessionState = {
  kEnc: null,
  adminSecret: null,
  saltEncB64: '',
  saltAuthB64: '',
  vault: null,
  timeOffsetMs: 0,
  clipboardTimer: null,
  visibilityTimer: null,
  timerInterval: null
};

let accountToDeleteId = null;
let accountToEditId = null;

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
const exportBtn = document.getElementById('exportBtn');
const importFileInput = document.getElementById('importFileInput');
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

// Delete Modal Elements
const deleteConfirmModal = document.getElementById('deleteConfirmModal');
const deleteConfirmText = document.getElementById('deleteConfirmText');
const cancelDeleteBtn = document.getElementById('cancelDeleteBtn');
const confirmDeleteBtn = document.getElementById('confirmDeleteBtn');

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
    const { kEnc } = await deriveKeysWithWorker(password, saltEnc, saltAuth);

    sessionState.kEnc = kEnc;
    sessionState.saltEncB64 = bufferToBase64(saltEnc);
    sessionState.saltAuthB64 = bufferToBase64(saltAuth);

    // Query Cloud KV using plaintext password (ADMIN secret auth)
    const { data: cloudData, timeOffsetMs, error } = await fetchCloudVault(password);
    
    if (error === 'UNAUTHORIZED_ADMIN') {
      throw new Error('UNAUTHORIZED_ADMIN');
    }
    
    sessionState.adminSecret = password;
    sessionState.timeOffsetMs = timeOffsetMs;
    
    console.log('Fetched cloudData for login:', cloudData);

    let decrypted = null;
    let hasExistingData = false;

    if (cloudData && cloudData.ciphertext) {
      hasExistingData = true;
      try {
        decrypted = await decryptVaultPayload(cloudData.iv, cloudData.ciphertext, kEnc);
      } catch (err) {
        throw new Error('INVALID_MAGIC');
      }
    }

    if (!decrypted && !hasExistingData) {
      // First time vault creation for this master password
      sessionState.vault = {
        magic: 'VALID_VAULT_V1',
        version: 1,
        updatedAt: Date.now(),
        accounts: []
      };
      await saveVault();
    } else if (decrypted) {
      sessionState.vault = decrypted;
    } else {
      throw new Error('INVALID_MAGIC');
    }

    showDashboard();
  } catch (err) {
    if (err.message !== 'UNAUTHORIZED_ADMIN') {
      console.error(err);
    }
    if (err.message === 'UNAUTHORIZED_ADMIN') {
      lockError.textContent = '密码错误';
    } else if (err.message && err.message.includes('reading \'digest\'')) {
      lockError.textContent = '安全环境受限：必须使用 https:// 或 localhost 访问才能使用加密功能！';
    } else {
      lockError.textContent = err.message === 'INVALID_MAGIC' 
        ? '原主密码错误！' 
        : '密码库解密失败！(' + (err.message || '未知错误') + ')';
    }
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

  const syncRes = await pushCloudVault(payload, sessionState.adminSecret);

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
      await pushCloudVault(mergedPayload, sessionState.adminSecret);
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
        <button class="edit-account-btn" title="编辑账号" aria-label="Edit Account">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 20h9"></path>
            <path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path>
          </svg>
        </button>
        <button class="delete-account-btn" title="删除账号" aria-label="Delete Account">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="3 6 5 6 21 6"></polyline>
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
          </svg>
        </button>
      </div>
    `;

    card.querySelector('.totp-code-display').addEventListener('click', (e) => {
      e.stopPropagation();
      const codeText = card.querySelector('.totp-code-display').dataset.rawCode;
      if (codeText) copyToClipboard(codeText);
    });

    card.querySelector('.edit-account-btn').addEventListener('click', (e) => {
      e.stopPropagation();
      accountToEditId = acc.id;
      document.querySelector('#addModal .modal-title').textContent = '编辑 2FA 验证账号';
      document.getElementById('addIssuerInput').value = acc.issuer;
      document.getElementById('addAccountInput').value = acc.account;
      document.getElementById('addSecretInput').value = acc.secret;
      document.getElementById('addAlgoSelect').value = acc.algo || 'SHA1';
      addModal.classList.add('active');
    });

    card.querySelector('.delete-account-btn').addEventListener('click', (e) => {
      e.stopPropagation();
      accountToDeleteId = acc.id;
      deleteConfirmText.textContent = `确定要删除【${acc.issuer} (${acc.account})】验证码账号吗？删除后云端将同步更新，且不可撤销。`;
      deleteConfirmModal.classList.add('active');
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

// Delete Account Modal Actions
cancelDeleteBtn.addEventListener('click', () => {
  deleteConfirmModal.classList.remove('active');
  accountToDeleteId = null;
});

confirmDeleteBtn.addEventListener('click', async () => {
  if (!accountToDeleteId || !sessionState.vault) return;

  confirmDeleteBtn.disabled = true;
  confirmDeleteBtn.textContent = '删除并同步中...';

  try {
    sessionState.vault.accounts = sessionState.vault.accounts.filter(a => a.id !== accountToDeleteId);
    await saveVault();
    renderAccountListStructure();
    updateTotpCodesInPlace();
    showToast('2FA 验证账号已成功删除！');
    deleteConfirmModal.classList.remove('active');
  } catch (err) {
    alert('删除账号失败: ' + err.message);
  } finally {
    confirmDeleteBtn.disabled = false;
    confirmDeleteBtn.textContent = '确认删除';
    accountToDeleteId = null;
  }
});

// In-Place Update TOTP codes & timer rings every 1s safely
async function updateTotpCodesInPlace() {
  if (!sessionState.vault) return;

  const cardElements = accountList.querySelectorAll('.account-card-pro');
  for (const card of cardElements) {
    const accId = card.dataset.accId;
    const acc = sessionState.vault.accounts.find((a) => a.id === accId);
    if (!acc) continue;

    try {
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

      if (codeDisplay) {
        codeDisplay.textContent = formattedCode;
        codeDisplay.dataset.rawCode = codeRaw;
      }
      if (ringText) ringText.textContent = rem;

      if (ringCircle) {
        const strokeOffset = 88 * (1 - rem / period);
        ringCircle.style.strokeDashoffset = strokeOffset;
        if (rem <= 5) {
          ringCircle.classList.add('warning');
        } else {
          ringCircle.classList.remove('warning');
        }
      }
    } catch (err) {
      const codeDisplay = card.querySelector('.totp-code-display');
      if (codeDisplay) codeDisplay.textContent = 'Err Key';
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

// Lock & Export
exportBtn.addEventListener('click', exportToJSON);
if (importFileInput) {
  importFileInput.addEventListener('change', handleImportJSON);
}
lockBtn.addEventListener('click', lockVault);

function exportToJSON() {
  if (!sessionState.vault || !sessionState.vault.accounts) return;
  
  const exportData = sessionState.vault.accounts.map(acc => {
    const { id, createdAt, ...rest } = acc;
    return rest;
  });
  
  const data = JSON.stringify(exportData, null, 2);
  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  
  const now = new Date();
  const dateStr = now.getFullYear() +
    String(now.getMonth() + 1).padStart(2, '0') +
    String(now.getDate()).padStart(2, '0') + '_' +
    String(now.getHours()).padStart(2, '0') +
    String(now.getMinutes()).padStart(2, '0') +
    String(now.getSeconds()).padStart(2, '0');
    
  a.download = `2fa_vault_export_${dateStr}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast('数据已成功导出！');
}

function handleImportJSON(e) {
  const file = e.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = async function(event) {
    try {
      const importedData = JSON.parse(event.target.result);
      if (!Array.isArray(importedData)) {
        throw new Error('JSON 数据格式不正确，必须是一个数组。');
      }

      let addedCount = 0;
      let duplicateCount = 0;
      
      const existingSecrets = new Set(sessionState.vault.accounts.map(acc => acc.secret));

      for (const item of importedData) {
        if (!item.secret) continue;
        
        if (existingSecrets.has(item.secret)) {
          duplicateCount++;
          continue;
        }

        const newAccount = {
          id: crypto.randomUUID(),
          issuer: item.issuer || 'Unknown',
          account: item.account || '',
          secret: item.secret,
          algo: item.algo || 'SHA1',
          digits: item.digits || 6,
          period: item.period || 30,
          pinned: item.pinned || false,
          createdAt: Date.now()
        };

        sessionState.vault.accounts.push(newAccount);
        existingSecrets.add(item.secret);
        addedCount++;
      }

      if (addedCount > 0) {
        await saveVault();
        renderAccountListStructure();
        updateTotpCodesInPlace();
        showToast(`成功导入 ${addedCount} 个账号！${duplicateCount > 0 ? ` (跳过 ${duplicateCount} 个重复项)` : ''}`);
      } else if (duplicateCount > 0) {
        showToast(`没有导入新账号，跳过了 ${duplicateCount} 个重复项。`);
      } else {
        showToast('文件中未找到有效的账号数据。');
      }
    } catch (err) {
      showToast('导入失败：' + err.message);
    }
    
    e.target.value = '';
  };
  reader.readAsText(file);
}

function lockVault() {
  sessionState.kEnc = null;
  sessionState.adminSecret = null;
  sessionState.vault = null;
  if (sessionState.timerInterval) clearInterval(sessionState.timerInterval);
  dashboardView.style.display = 'none';
  lockView.style.display = 'block';
  lockBtn.style.display = 'none';
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
    } else if (deleteConfirmModal.classList.contains('active')) {
      deleteConfirmModal.classList.remove('active');
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

// Add/Edit modal
addAccountBtn.addEventListener('click', () => {
  accountToEditId = null;
  document.querySelector('#addModal .modal-title').textContent = '添加 2FA 验证账号';
  document.getElementById('addIssuerInput').value = '';
  document.getElementById('addAccountInput').value = '';
  document.getElementById('addSecretInput').value = '';
  document.getElementById('addAlgoSelect').value = 'SHA1';
  addModal.classList.add('active');
});
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
    if (accountToEditId) {
      const idx = sessionState.vault.accounts.findIndex(a => a.id === accountToEditId);
      if (idx !== -1) {
        sessionState.vault.accounts[idx].issuer = issuer;
        sessionState.vault.accounts[idx].account = account;
        sessionState.vault.accounts[idx].secret = secret;
        sessionState.vault.accounts[idx].algo = algo;
        sessionState.vault.accounts[idx].digits = algo === 'STEAM' ? 5 : 6;
      }
    } else {
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
    }

    await saveVault();
    addModal.classList.remove('active');
    document.getElementById('addIssuerInput').value = '';
    document.getElementById('addAccountInput').value = '';
    document.getElementById('addSecretInput').value = '';
    renderAccountListStructure();
    updateTotpCodesInPlace();
    showToast(accountToEditId ? '账号更新并同步成功！' : '新 2FA 账号添加并同步成功！');
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
