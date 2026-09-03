const RECORD_TYPES = new Set(['injection', 'measurement', 'symptom']);
const INJECTION_SITES = new Set(['', 'abdomen-left', 'abdomen-right', 'thigh-left', 'thigh-right', 'arm-left', 'arm-right', 'other']);

function cleanText(value, maxLength, { allowNewlines = false } = {}) {
  if (typeof value !== 'string') return '';
  const normalized = value.normalize('NFC');
  const safe = allowNewlines
    ? normalized.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
    : normalized.replace(/[\u0000-\u001F\u007F]/g, ' ');
  return safe.trim().replace(allowNewlines ? /[ \t]+/g : /\s+/g, ' ').slice(0, maxLength);
}

function parseBoundedNumber(value, min, max, decimals) {
  if (value === '' || value === null || value === undefined) return null;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < min || parsed > max) throw new Error('Numeric value is outside the allowed range.');
  const factor = 10 ** decimals;
  return Math.round(parsed * factor) / factor;
}

function validateLocalDateTime(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value)) throw new Error('A valid date and time is required.');
  const [datePart, timePart] = value.split('T');
  const [year, month, day] = datePart.split('-').map(Number);
  const [hour, minute] = timePart.split(':').map(Number);
  const date = new Date(year, month - 1, day, hour, minute, 0, 0);
  if (
    date.getFullYear() !== year || date.getMonth() !== month - 1 || date.getDate() !== day ||
    date.getHours() !== hour || date.getMinutes() !== minute
  ) throw new Error('Invalid date and time.');

  const now = Date.now();
  if (date.getTime() > now + 24 * 60 * 60 * 1000) throw new Error('Record time cannot be more than 24 hours in the future.');
  if (date.getTime() < Date.UTC(2000, 0, 1)) throw new Error('Record date is outside the supported range.');
  return date.toISOString();
}

export function validatePassphrase(passphrase, confirmation) {
  if (typeof passphrase !== 'string' || typeof confirmation !== 'string') throw new Error('Passphrase required.');
  const normalized = passphrase.normalize('NFC');
  if (normalized.length < 12 || normalized.length > 256) throw new Error('Passphrase must be 12–256 characters.');
  if (normalized !== confirmation.normalize('NFC')) throw new Error('Passphrases do not match.');
  return normalized;
}

export function buildValidatedRecord(formData) {
  const type = cleanText(formData.get('recordType') ?? '', 20);
  if (!RECORD_TYPES.has(type)) throw new Error('Invalid record type.');

  const record = {
    schemaVersion: 1,
    type,
    timestamp: validateLocalDateTime(formData.get('recordDateTime') ?? ''),
    notes: cleanText(formData.get('notes') ?? '', 2000, { allowNewlines: true }),
  };

  if (type === 'injection') {
    const medication = cleanText(formData.get('medication') ?? '', 80);
    const doseMg = parseBoundedNumber(formData.get('doseMg'), 0.001, 100, 3);
    const injectionSite = cleanText(formData.get('injectionSite') ?? '', 30);
    if (!medication) throw new Error('Medication is required for an injection.');
    if (doseMg === null) throw new Error('Dose is required for an injection.');
    if (!INJECTION_SITES.has(injectionSite)) throw new Error('Invalid injection site.');
    Object.assign(record, { medication, doseMg, injectionSite });
  } else if (type === 'measurement') {
    const weightLb = parseBoundedNumber(formData.get('weightLb'), 20, 1500, 1);
    const waistIn = parseBoundedNumber(formData.get('waistIn'), 10, 120, 1);
    if (weightLb === null && waistIn === null) throw new Error('Enter at least one measurement.');
    Object.assign(record, { weightLb, waistIn });
  } else if (type === 'symptom') {
    const symptomName = cleanText(formData.get('symptomName') ?? '', 80);
    const severity = parseBoundedNumber(formData.get('severity'), 1, 5, 0);
    if (!symptomName) throw new Error('Symptom name is required.');
    Object.assign(record, { symptomName, severity });
  }

  return record;
}


export function validateDecryptedRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || value.schemaVersion !== 1) {
    throw new Error('Invalid decrypted record.');
  }
  if (!RECORD_TYPES.has(value.type)) throw new Error('Invalid decrypted record type.');
  const timestamp = new Date(value.timestamp);
  if (typeof value.timestamp !== 'string' || Number.isNaN(timestamp.getTime())) throw new Error('Invalid decrypted record timestamp.');
  if (typeof value.notes !== 'string' || value.notes.length > 2000) throw new Error('Invalid decrypted record notes.');

  const safe = { schemaVersion: 1, type: value.type, timestamp: timestamp.toISOString(), notes: cleanText(value.notes, 2000, { allowNewlines: true }) };
  if (value.type === 'injection') {
    const medication = cleanText(value.medication, 80);
    const doseMg = parseBoundedNumber(value.doseMg, 0.001, 100, 3);
    const injectionSite = cleanText(value.injectionSite ?? '', 30);
    if (!medication || doseMg === null || !INJECTION_SITES.has(injectionSite)) throw new Error('Invalid injection record.');
    Object.assign(safe, { medication, doseMg, injectionSite });
  } else if (value.type === 'measurement') {
    const weightLb = parseBoundedNumber(value.weightLb, 20, 1500, 1);
    const waistIn = parseBoundedNumber(value.waistIn, 10, 120, 1);
    if (weightLb === null && waistIn === null) throw new Error('Invalid measurement record.');
    Object.assign(safe, { weightLb, waistIn });
  } else {
    const symptomName = cleanText(value.symptomName, 80);
    const severity = parseBoundedNumber(value.severity, 1, 5, 0);
    if (!symptomName || severity === null) throw new Error('Invalid symptom record.');
    Object.assign(safe, { symptomName, severity });
  }
  return safe;
}

export function validateBackupPayload(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('Backup is not a valid object.');
  if (payload.format !== 'private-glp1-tracker-backup' || payload.formatVersion !== 1) throw new Error('Unsupported backup format.');
  if (!payload.meta || typeof payload.meta !== 'object' || Array.isArray(payload.meta)) throw new Error('Backup metadata is missing.');
  if (!Array.isArray(payload.records) || payload.records.length > 100_000) throw new Error('Backup record list is invalid.');

  const requiredMeta = ['vaultVersion', 'kdf', 'salt', 'iterations', 'keyCheck'];
  for (const key of requiredMeta) {
    if (!(key in payload.meta)) throw new Error('Backup metadata is incomplete.');
  }
  if (payload.meta.vaultVersion !== 1 || payload.meta.kdf !== 'PBKDF2-HMAC-SHA-256') throw new Error('Unsupported backup cryptography.');
  if (!Number.isInteger(payload.meta.iterations) || payload.meta.iterations < 600_000 || payload.meta.iterations > 5_000_000) throw new Error('Unsafe or unsupported KDF work factor.');
  if (typeof payload.meta.salt !== 'string' || payload.meta.salt.length < 20 || payload.meta.salt.length > 64) throw new Error('Invalid backup salt.');
  if (!payload.meta.keyCheck || typeof payload.meta.keyCheck.iv !== 'string' || payload.meta.keyCheck.iv.length > 64 || typeof payload.meta.keyCheck.ciphertext !== 'string' || payload.meta.keyCheck.ciphertext.length > 2048) throw new Error('Invalid backup key check.');

  const ids = new Set();
  for (const record of payload.records) {
    if (!record || typeof record !== 'object' || record.version !== 1) throw new Error('Backup contains an invalid encrypted record.');
    if (typeof record.id !== 'string' || !/^[0-9a-f-]{20,80}$/i.test(record.id) || ids.has(record.id)) throw new Error('Backup contains an invalid record identifier.');
    if (typeof record.iv !== 'string' || record.iv.length > 64 || typeof record.ciphertext !== 'string' || record.ciphertext.length > 100_000) throw new Error('Backup contains an invalid encrypted payload.');
    ids.add(record.id);
  }
  return payload;
}
