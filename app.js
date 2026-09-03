import {
  openDatabase, getMeta, setMeta, getAllMeta, putEncryptedRecord,
  getAllEncryptedRecords, deleteEncryptedRecord, replaceVault, deleteDatabase,
} from './db.js';
import {
  KDF_ITERATIONS, bytesToBase64, randomBytes, deriveVaultKey, createKeyCheck,
  verifyKeyCheck, encryptRecord, decryptRecord,
} from './crypto.js';
import { validatePassphrase, buildValidatedRecord, validateDecryptedRecord, validateBackupPayload } from './validation.js';

const el = (id) => document.getElementById(id);
const views = { setup: el('setupView'), unlock: el('unlockView'), main: el('mainView'), unsupported: el('unsupportedView') };
let db = null;
let vaultKey = null;
let decryptedRecords = [];
let toastTimer = null;
let inactivityTimer = null;
const AUTO_LOCK_MS = 5 * 60 * 1000;

function showOnly(viewName) {
  for (const [name, node] of Object.entries(views)) node.classList.toggle('hidden', name !== viewName);
  el('lockButton').classList.toggle('hidden', viewName !== 'main');
}

function showToast(message) {
  clearTimeout(toastTimer);
  const toast = el('toast');
  toast.textContent = message;
  toast.classList.remove('hidden');
  toastTimer = setTimeout(() => toast.classList.add('hidden'), 4000);
}

function setBusy(form, busy) {
  for (const control of form.elements) control.disabled = busy;
}

function formatDateTime(timestamp) {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return 'Invalid date';
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}

function setDefaultDateTime() {
  const now = new Date();
  const local = new Date(now.getTime() - now.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
  el('recordDateTime').value = local;
}

function supportsRequiredApis() {
  return window.isSecureContext && 'indexedDB' in window && 'crypto' in window && Boolean(crypto.subtle);
}

async function requestPersistentStorage() {
  const status = el('storageStatus');
  if (!navigator.storage?.persisted) {
    status.textContent = 'Browser-managed';
    return;
  }
  try {
    let persistent = await navigator.storage.persisted();
    if (!persistent && navigator.storage.persist) persistent = await navigator.storage.persist();
    status.textContent = persistent ? 'Persistent' : 'Best effort';
  } catch {
    status.textContent = 'Best effort';
  }
}

async function initializeVault(passphrase) {
  const salt = bytesToBase64(randomBytes(16));
  const key = await deriveVaultKey(passphrase, salt, KDF_ITERATIONS);
  const keyCheck = await createKeyCheck(key);
  await setMeta(db, 'vaultVersion', 1);
  await setMeta(db, 'kdf', 'PBKDF2-HMAC-SHA-256');
  await setMeta(db, 'salt', salt);
  await setMeta(db, 'iterations', KDF_ITERATIONS);
  await setMeta(db, 'keyCheck', keyCheck);
  vaultKey = key;
}

async function unlockVault(passphrase) {
  const [vaultVersion, kdf, salt, iterations, keyCheck] = await Promise.all([
    getMeta(db, 'vaultVersion'), getMeta(db, 'kdf'), getMeta(db, 'salt'), getMeta(db, 'iterations'), getMeta(db, 'keyCheck'),
  ]);
  if (vaultVersion !== 1 || kdf !== 'PBKDF2-HMAC-SHA-256' || typeof salt !== 'string' || !Number.isInteger(iterations) || !keyCheck) {
    throw new Error('Local vault metadata is invalid.');
  }
  const key = await deriveVaultKey(passphrase.normalize('NFC'), salt, iterations);
  if (!(await verifyKeyCheck(key, keyCheck))) throw new Error('Incorrect passphrase or damaged vault.');
  vaultKey = key;
}

async function refreshRecords() {
  if (!vaultKey) return;
  const encryptedRecords = await getAllEncryptedRecords(db);
  const results = await Promise.allSettled(encryptedRecords.map(async (encrypted) => ({
    id: encrypted.id,
    data: validateDecryptedRecord(await decryptRecord(vaultKey, encrypted)),
  })));
  decryptedRecords = results.filter((r) => r.status === 'fulfilled').map((r) => r.value);
  const failed = results.length - decryptedRecords.length;
  decryptedRecords.sort((a, b) => new Date(b.data.timestamp) - new Date(a.data.timestamp));
  el('recordCount').textContent = String(decryptedRecords.length);
  renderSummary();
  renderHistory();
  if (failed > 0) showToast(`${failed} encrypted record(s) could not be authenticated and were not displayed.`);
}

function renderSummary() {
  const injection = decryptedRecords.find(({ data }) => data.type === 'injection');
  const measurement = decryptedRecords.find(({ data }) => data.type === 'measurement' && data.weightLb !== null);
  const symptom = decryptedRecords.find(({ data }) => data.type === 'symptom');

  el('lastInjection').textContent = injection
    ? `${injection.data.medication} ${injection.data.doseMg} mg · ${formatDateTime(injection.data.timestamp)}`
    : '—';
  el('latestWeight').textContent = measurement
    ? `${measurement.data.weightLb} lb · ${formatDateTime(measurement.data.timestamp)}`
    : '—';
  el('latestSymptom').textContent = symptom
    ? `${symptom.data.symptomName} (${symptom.data.severity}/5) · ${formatDateTime(symptom.data.timestamp)}`
    : '—';
}

function describeRecord(record) {
  const parts = [];
  if (record.type === 'injection') {
    parts.push(`${record.medication} — ${record.doseMg} mg`);
    if (record.injectionSite) parts.push(record.injectionSite.replaceAll('-', ' '));
  } else if (record.type === 'measurement') {
    if (record.weightLb !== null) parts.push(`Weight: ${record.weightLb} lb`);
    if (record.waistIn !== null) parts.push(`Waist: ${record.waistIn} in`);
  } else if (record.type === 'symptom') {
    parts.push(`${record.symptomName} — severity ${record.severity}/5`);
  }
  if (record.notes) parts.push(record.notes);
  return parts.join('\n');
}

function renderHistory() {
  const list = el('historyList');
  list.replaceChildren();
  const filter = el('historyFilter').value;
  const records = filter === 'all' ? decryptedRecords : decryptedRecords.filter(({ data }) => data.type === filter);

  if (records.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'empty';
    empty.textContent = 'No records to display.';
    list.append(empty);
    return;
  }

  for (const { id, data } of records) {
    const item = document.createElement('article');
    item.className = 'history-item';

    const head = document.createElement('div');
    head.className = 'history-head';
    const type = document.createElement('span');
    type.className = 'history-type';
    type.textContent = data.type;
    const date = document.createElement('span');
    date.className = 'history-date';
    date.textContent = formatDateTime(data.timestamp);
    head.append(type, date);

    const body = document.createElement('div');
    body.className = 'history-body';
    body.textContent = describeRecord(data);

    const actions = document.createElement('div');
    actions.className = 'history-actions';
    const deleteButton = document.createElement('button');
    deleteButton.type = 'button';
    deleteButton.className = 'danger';
    deleteButton.textContent = 'Delete';
    deleteButton.dataset.deleteRecordId = id;
    actions.append(deleteButton);

    item.append(head, body, actions);
    list.append(item);
  }
}

function updateConditionalFields() {
  const type = el('recordType').value;
  el('injectionFields').classList.toggle('hidden', type !== 'injection');
  el('measurementFields').classList.toggle('hidden', type !== 'measurement');
  el('symptomFields').classList.toggle('hidden', type !== 'symptom');
}

function wipeSensitiveView() {
  decryptedRecords = [];
  el('historyList').replaceChildren();
  el('recordCount').textContent = '0';
  el('lastInjection').textContent = '—';
  el('latestWeight').textContent = '—';
  el('latestSymptom').textContent = '—';
  el('recordForm').reset();
  updateConditionalFields();
}

function resetInactivityTimer() {
  clearTimeout(inactivityTimer);
  if (!vaultKey) return;
  inactivityTimer = setTimeout(() => {
    if (vaultKey) {
      lockVault();
      showToast('Vault locked after 5 minutes of inactivity.');
    }
  }, AUTO_LOCK_MS);
}

function lockVault() {
  clearTimeout(inactivityTimer);
  inactivityTimer = null;
  vaultKey = null;
  wipeSensitiveView();
  el('passphrase').value = '';
  el('newPassphrase').value = '';
  el('confirmPassphrase').value = '';
  showOnly('unlock');
}

async function exportBackup() {
  const meta = await getAllMeta(db);
  const records = await getAllEncryptedRecords(db);
  const payload = {
    format: 'private-glp1-tracker-backup',
    formatVersion: 1,
    exportedAt: new Date().toISOString(),
    meta,
    records,
  };
  validateBackupPayload(payload);
  const blob = new Blob([JSON.stringify(payload)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  try {
    const link = document.createElement('a');
    link.href = url;
    link.download = `glp1-tracker-${new Date().toISOString().slice(0, 10)}.glp1`;
    link.rel = 'noopener';
    document.body.append(link);
    link.click();
    link.remove();
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}

async function importBackup(file) {
  if (!(file instanceof File)) throw new Error('Choose a backup file.');
  if (file.size <= 0 || file.size > 25 * 1024 * 1024) throw new Error('Backup file size is invalid.');
  const text = await file.text();
  let parsed;
  try { parsed = JSON.parse(text); } catch { throw new Error('Backup file is not valid JSON.'); }
  const payload = validateBackupPayload(parsed);

  const currentMeta = await getAllMeta(db);
  const currentRecords = await getAllEncryptedRecords(db);
  const restorePoint = { meta: currentMeta, records: currentRecords };
  try {
    await replaceVault(db, payload.meta, payload.records);
  } catch {
    try { await replaceVault(db, restorePoint.meta, restorePoint.records); } catch { /* fail closed; caller surfaces generic error */ }
    throw new Error('Backup import failed. Existing data was preserved where possible.');
  }
  lockVault();
  showToast('Backup imported. Unlock it using the backup passphrase.');
}

function wireEvents() {
  el('setupForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    setBusy(form, true);
    try {
      const passphrase = validatePassphrase(el('newPassphrase').value, el('confirmPassphrase').value);
      await initializeVault(passphrase);
      el('newPassphrase').value = '';
      el('confirmPassphrase').value = '';
      showOnly('main');
      setDefaultDateTime();
      await Promise.all([requestPersistentStorage(), refreshRecords()]);
      resetInactivityTimer();
      showToast('Encrypted local vault created.');
    } catch (error) {
      showToast(error instanceof Error ? error.message : 'Unable to create vault.');
    } finally {
      setBusy(form, false);
    }
  });

  el('unlockForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    setBusy(form, true);
    try {
      await unlockVault(el('passphrase').value);
      el('passphrase').value = '';
      showOnly('main');
      setDefaultDateTime();
      await Promise.all([requestPersistentStorage(), refreshRecords()]);
      resetInactivityTimer();
    } catch {
      showToast('Unable to unlock. Check the passphrase and vault integrity.');
    } finally {
      setBusy(form, false);
    }
  });

  el('lockButton').addEventListener('click', lockVault);
  el('recordType').addEventListener('change', updateConditionalFields);
  el('historyFilter').addEventListener('change', renderHistory);

  el('recordForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!vaultKey) { lockVault(); return; }
    const form = event.currentTarget;
    setBusy(form, true);
    try {
      const record = buildValidatedRecord(new FormData(form));
      const id = crypto.randomUUID();
      const encrypted = await encryptRecord(vaultKey, id, record);
      await putEncryptedRecord(db, encrypted);
      form.reset();
      el('recordType').value = 'injection';
      updateConditionalFields();
      setDefaultDateTime();
      await refreshRecords();
      showToast('Record encrypted and saved locally.');
    } catch (error) {
      showToast(error instanceof Error ? error.message : 'Unable to save record.');
    } finally {
      setBusy(form, false);
    }
  });

  el('historyList').addEventListener('click', async (event) => {
    const target = event.target.closest('[data-delete-record-id]');
    if (!(target instanceof HTMLButtonElement) || !vaultKey) return;
    const id = target.dataset.deleteRecordId;
    if (!id || !confirm('Delete this encrypted record permanently?')) return;
    target.disabled = true;
    try {
      await deleteEncryptedRecord(db, id);
      await refreshRecords();
      showToast('Record deleted.');
    } catch {
      showToast('Unable to delete the record.');
      target.disabled = false;
    }
  });

  for (const tab of document.querySelectorAll('.tab')) {
    tab.addEventListener('click', () => {
      const selected = tab.dataset.tab;
      for (const candidate of document.querySelectorAll('.tab')) {
        const active = candidate === tab;
        candidate.classList.toggle('active', active);
        candidate.setAttribute('aria-selected', String(active));
      }
      for (const panel of document.querySelectorAll('.tab-panel')) panel.classList.add('hidden');
      el(`tab-${selected}`).classList.remove('hidden');
    });
  }

  el('exportButton').addEventListener('click', async () => {
    try { await exportBackup(); showToast('Encrypted backup prepared for saving.'); }
    catch { showToast('Unable to export backup.'); }
  });

  el('importFile').addEventListener('change', async (event) => {
    const input = event.currentTarget;
    const file = input.files?.[0];
    input.value = '';
    if (!file) return;
    if (!confirm('Importing will replace the current local vault. Continue?')) return;
    try { await importBackup(file); }
    catch (error) { showToast(error instanceof Error ? error.message : 'Unable to import backup.'); }
  });

  el('deleteVaultButton').addEventListener('click', async () => {
    if (!confirm('Delete ALL local tracker data? This cannot be undone without a backup.')) return;
    if (!confirm('Final confirmation: permanently delete the encrypted vault from this browser?')) return;
    try {
      vaultKey = null;
      wipeSensitiveView();
      db.close();
      db = null;
      await deleteDatabase();
      db = await openDatabase();
      showOnly('setup');
      showToast('Local vault deleted.');
    } catch {
      showToast('Unable to delete the local vault. Close other tracker windows and try again.');
    }
  });

  for (const eventName of ['pointerdown', 'keydown', 'touchstart']) {
    document.addEventListener(eventName, () => { if (vaultKey) resetInactivityTimer(); }, { passive: true });
  }
  document.addEventListener('visibilitychange', () => {
    if (vaultKey && document.visibilityState === 'hidden') resetInactivityTimer();
  });
}

async function boot() {
  if (window.top !== window.self || !supportsRequiredApis()) { showOnly('unsupported'); return; }
  wireEvents();
  updateConditionalFields();
  try {
    db = await openDatabase();
    const vaultVersion = await getMeta(db, 'vaultVersion');
    showOnly(vaultVersion === undefined ? 'setup' : 'unlock');
  } catch {
    showOnly('unsupported');
  }

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('./service-worker.js').catch(() => {
      // Offline installation can fail without affecting encrypted local storage.
    });
  }
}

boot();
