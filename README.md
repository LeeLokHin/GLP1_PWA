# Private GLP-1 Tracker PWA

A local-first, offline-capable GLP-1 tracker designed for iPhone. The PWA has no backend, no analytics, no account system, and no cloud database. Health records are encrypted before being written to IndexedDB.

## What it tracks
- Injections: medication, dose, date/time, injection site, notes
- Measurements: weight, waist, date/time, notes
- Symptoms: name, 1–5 severity, date/time, notes
- Encrypted history and summary
- Five-minute inactivity auto-lock with decrypted DOM wipe
- Encrypted backup export / validated restore

## Security assumptions
1. Serve only over HTTPS. Web Crypto and service workers require a secure context.
2. Protect the GitHub account/repository that publishes the app. A malicious change to `app.js` could read plaintext while the vault is unlocked.
3. Use a long, unique vault passphrase. It is not stored and cannot be recovered.
4. Keep a tested encrypted backup. Browser storage can still be deleted by the user, device reset, or platform storage management.
5. Do not add analytics, third-party scripts, remote fonts, or API calls without updating the threat model and CSP.

See `SECURITY.md` for the full threat model.

## Run locally
Service workers and Web Crypto should be tested in a secure context. `localhost` is treated as secure by modern browsers.

```bash
python3 -m http.server 8080
```

Then open `http://localhost:8080` on a development machine.

For iPhone installation, deploy to HTTPS, open the site in Safari, then use **Share → Add to Home Screen**.

## GitHub Pages deployment
1. Create a repository and copy these files into it.
2. Push to the `main` branch.
3. In GitHub repository settings, enable **Pages → Source: GitHub Actions**.
4. The included `.github/workflows/pages.yml` runs syntax/security smoke tests and then deploys the static app. Third-party GitHub Actions are pinned to immutable commit SHAs; Dependabot is configured to propose controlled updates.

The repository can be public because no user health data is committed. If you choose a private repository, verify the GitHub plan/Pages visibility behavior you require. The deployed application itself must still be treated as potentially public unless you have explicit access controls.

## Data storage
Plaintext health records exist only transiently in the unlocked page's memory. Persisted `records` entries contain:

```json
{
  "id": "random-uuid",
  "version": 1,
  "iv": "base64-random-96-bit-nonce",
  "ciphertext": "base64-aes-gcm-ciphertext-and-tag"
}
```

Vault metadata stores the KDF identifier, salt, work factor, and an encrypted key-check value. This metadata is not secret.

## Backup
**Export encrypted backup** creates a `.glp1` JSON file containing the encrypted records and required cryptographic metadata. On iPhone, save it via the system share/download workflow to iCloud Drive or another storage location you trust.

Import validates the file shape and replaces the local vault. You must unlock with the passphrase that encrypted the imported vault.

## Why PBKDF2 instead of Argon2id?
Argon2id is the preferred memory-hard KDF. Safari's native Web Crypto API currently provides PBKDF2 but not Argon2id. This project intentionally has zero runtime dependencies, so it uses PBKDF2-HMAC-SHA-256 with 600,000 iterations rather than bundling a third-party WebAssembly crypto implementation. If you later accept a carefully pinned/audited Argon2id dependency, migrate the vault format rather than silently changing existing KDF parameters.

## Medical-use boundary
This is a personal logging tool, not a dosing calculator, prescribing system, diagnostic tool, or substitute for clinician/pharmacist guidance. It intentionally does not recommend dose changes.


## Verification

With Node.js 22+ installed:

```bash
npm test
```

The smoke test verifies key derivation, correct/wrong passphrase behavior, AES-GCM round-trip, tamper rejection, and input range validation.
