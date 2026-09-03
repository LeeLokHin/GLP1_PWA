const DB_NAME = 'private-glp1-tracker';
const DB_VERSION = 1;
const META_STORE = 'meta';
const RECORDS_STORE = 'records';

function requestToPromise(request) {
  return new Promise((resolve, reject) => {
    request.addEventListener('success', () => resolve(request.result), { once: true });
    request.addEventListener('error', () => reject(new Error('Database operation failed.')), { once: true });
  });
}

function transactionDone(transaction) {
  return new Promise((resolve, reject) => {
    transaction.addEventListener('complete', resolve, { once: true });
    transaction.addEventListener('abort', () => reject(new Error('Database transaction was aborted.')), { once: true });
    transaction.addEventListener('error', () => reject(new Error('Database transaction failed.')), { once: true });
  });
}

export async function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.addEventListener('upgradeneeded', () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(META_STORE)) db.createObjectStore(META_STORE);
      if (!db.objectStoreNames.contains(RECORDS_STORE)) db.createObjectStore(RECORDS_STORE, { keyPath: 'id' });
    });

    request.addEventListener('success', () => resolve(request.result), { once: true });
    request.addEventListener('error', () => reject(new Error('Unable to open the local database.')), { once: true });
    request.addEventListener('blocked', () => reject(new Error('Database upgrade is blocked by another open app window.')), { once: true });
  });
}

export async function getMeta(db, key) {
  const tx = db.transaction(META_STORE, 'readonly');
  return requestToPromise(tx.objectStore(META_STORE).get(key));
}

export async function setMeta(db, key, value) {
  const tx = db.transaction(META_STORE, 'readwrite');
  tx.objectStore(META_STORE).put(value, key);
  await transactionDone(tx);
}

export async function getAllMeta(db) {
  const tx = db.transaction(META_STORE, 'readonly');
  const store = tx.objectStore(META_STORE);
  const [keys, values] = await Promise.all([
    requestToPromise(store.getAllKeys()),
    requestToPromise(store.getAll()),
  ]);
  return Object.fromEntries(keys.map((key, index) => [key, values[index]]));
}

export async function putEncryptedRecord(db, record) {
  const tx = db.transaction(RECORDS_STORE, 'readwrite');
  tx.objectStore(RECORDS_STORE).put(record);
  await transactionDone(tx);
}

export async function getAllEncryptedRecords(db) {
  const tx = db.transaction(RECORDS_STORE, 'readonly');
  return requestToPromise(tx.objectStore(RECORDS_STORE).getAll());
}

export async function deleteEncryptedRecord(db, id) {
  const tx = db.transaction(RECORDS_STORE, 'readwrite');
  tx.objectStore(RECORDS_STORE).delete(id);
  await transactionDone(tx);
}

export async function replaceVault(db, meta, records) {
  const tx = db.transaction([META_STORE, RECORDS_STORE], 'readwrite');
  const metaStore = tx.objectStore(META_STORE);
  const recordStore = tx.objectStore(RECORDS_STORE);
  metaStore.clear();
  recordStore.clear();
  for (const [key, value] of Object.entries(meta)) metaStore.put(value, key);
  for (const record of records) recordStore.put(record);
  await transactionDone(tx);
}

export async function deleteDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(DB_NAME);
    request.addEventListener('success', resolve, { once: true });
    request.addEventListener('error', () => reject(new Error('Unable to delete local database.')), { once: true });
    request.addEventListener('blocked', () => reject(new Error('Close other tracker windows before deleting the vault.')), { once: true });
  });
}
