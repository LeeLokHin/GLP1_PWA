const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export const KDF_ITERATIONS = 600_000;
export const CRYPTO_VERSION = 1;
const KEY_CHECK_TEXT = 'private-glp1-tracker-key-check-v1';

export function bytesToBase64(bytes) {
  let binary = '';
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (const byte of view) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function base64ToBytes(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 10_000_000) {
    throw new Error('Invalid encoded value.');
  }
  try {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    throw new Error('Invalid encoded value.');
  }
}

export function randomBytes(length) {
  if (!Number.isInteger(length) || length < 12 || length > 64) throw new Error('Invalid random byte request.');
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

export async function deriveVaultKey(passphrase, saltBase64, iterations = KDF_ITERATIONS) {
  if (typeof passphrase !== 'string') throw new Error('Passphrase required.');
  const normalizedPassphrase = passphrase.normalize('NFC');
  if (normalizedPassphrase.length < 12 || normalizedPassphrase.length > 256) throw new Error('Invalid passphrase length.');
  if (!Number.isInteger(iterations) || iterations < 600_000 || iterations > 5_000_000) throw new Error('Unsupported KDF settings.');

  const salt = base64ToBytes(saltBase64);
  if (salt.byteLength !== 16) throw new Error('Invalid KDF salt.');

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(normalizedPassphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey'],
  );

  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function encryptBytes(key, plaintextBytes, additionalData) {
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: encoder.encode(additionalData), tagLength: 128 },
    key,
    plaintextBytes,
  );
  return { iv: bytesToBase64(iv), ciphertext: bytesToBase64(ciphertext) };
}

async function decryptBytes(key, encrypted, additionalData) {
  if (!encrypted || typeof encrypted.iv !== 'string' || typeof encrypted.ciphertext !== 'string') {
    throw new Error('Malformed encrypted payload.');
  }
  const iv = base64ToBytes(encrypted.iv);
  if (iv.byteLength !== 12) throw new Error('Invalid encryption nonce.');
  try {
    return await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: encoder.encode(additionalData), tagLength: 128 },
      key,
      base64ToBytes(encrypted.ciphertext),
    );
  } catch {
    throw new Error('Unable to decrypt data.');
  }
}

export async function createKeyCheck(key) {
  return encryptBytes(key, encoder.encode(KEY_CHECK_TEXT), 'glp1-key-check-v1');
}

export async function verifyKeyCheck(key, keyCheck) {
  try {
    const plaintext = await decryptBytes(key, keyCheck, 'glp1-key-check-v1');
    return decoder.decode(plaintext) === KEY_CHECK_TEXT;
  } catch {
    return false;
  }
}

export async function encryptRecord(key, id, record) {
  if (typeof id !== 'string' || id.length < 20 || id.length > 80) throw new Error('Invalid record identifier.');
  const plaintext = encoder.encode(JSON.stringify(record));
  if (plaintext.byteLength > 50_000) throw new Error('Record is too large.');
  const encrypted = await encryptBytes(key, plaintext, `glp1-record-v1:${id}`);
  return { id, version: CRYPTO_VERSION, ...encrypted };
}

export async function decryptRecord(key, encryptedRecord) {
  if (!encryptedRecord || encryptedRecord.version !== CRYPTO_VERSION || typeof encryptedRecord.id !== 'string') {
    throw new Error('Unsupported encrypted record.');
  }
  const plaintext = await decryptBytes(key, encryptedRecord, `glp1-record-v1:${encryptedRecord.id}`);
  try {
    return JSON.parse(decoder.decode(plaintext));
  } catch {
    throw new Error('Decrypted record is invalid.');
  }
}
