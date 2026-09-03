import assert from 'node:assert/strict';
import {
  bytesToBase64,
  randomBytes,
  deriveVaultKey,
  createKeyCheck,
  verifyKeyCheck,
  encryptRecord,
  decryptRecord,
} from '../crypto.js';
import { buildValidatedRecord, validateDecryptedRecord } from '../validation.js';

const salt = bytesToBase64(randomBytes(16));
const key = await deriveVaultKey('correct horse battery staple', salt);
const keyCheck = await createKeyCheck(key);
assert.equal(await verifyKeyCheck(key, keyCheck), true);

const wrongKey = await deriveVaultKey('different long unique passphrase', salt);
assert.equal(await verifyKeyCheck(wrongKey, keyCheck), false);

const plaintext = {
  schemaVersion: 1,
  type: 'injection',
  timestamp: new Date().toISOString(),
  notes: 'test',
  medication: 'semaglutide',
  doseMg: 2.5,
  injectionSite: 'abdomen-left',
};
const id = crypto.randomUUID();
const encrypted = await encryptRecord(key, id, plaintext);
assert.notEqual(encrypted.ciphertext.includes('semaglutide'), true);
assert.deepEqual(await decryptRecord(key, encrypted), plaintext);

const tampered = { ...encrypted, ciphertext: `${encrypted.ciphertext.slice(0, -4)}AAAA` };
await assert.rejects(() => decryptRecord(key, tampered));

const form = new FormData();
form.set('recordType', 'injection');
const now = new Date();
const local = new Date(now.getTime() - now.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
form.set('recordDateTime', local);
form.set('medication', '  semaglutide  ');
form.set('doseMg', '2.5');
form.set('injectionSite', 'abdomen-left');
form.set('notes', '<img src=x onerror=alert(1)>');
const validated = buildValidatedRecord(form);
assert.equal(validated.medication, 'semaglutide');
assert.equal(validated.doseMg, 2.5);
assert.equal(validateDecryptedRecord(validated).type, 'injection');

const badForm = new FormData();
badForm.set('recordType', 'injection');
badForm.set('recordDateTime', local);
badForm.set('medication', 'x');
badForm.set('doseMg', '9999');
await assert.rejects(async () => buildValidatedRecord(badForm));

console.log('security smoke tests: ok');
