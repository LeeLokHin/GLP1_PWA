# Security model

## Data classification
GLP-1 medication, weight, symptoms, and notes are treated as sensitive health information.

## Controls
- No backend and no telemetry.
- No third-party JavaScript, fonts, analytics, CDNs, API calls, or cookies.
- Medical record payloads are encrypted before IndexedDB persistence.
- AES-256-GCM provides authenticated encryption with a fresh 96-bit IV per encryption operation.
- The record UUID is bound to ciphertext as AES-GCM additional authenticated data (AAD).
- The passphrase is not stored. A non-extractable CryptoKey is derived in memory.
- PBKDF2-HMAC-SHA-256 uses 600,000 iterations and a random 128-bit salt.
- CSP prohibits network connections (`connect-src 'none'`) and inline/third-party scripts.
- User data is rendered with `textContent`; no user-controlled HTML is injected.
- Import accepts only bounded JSON files and validates schema, cryptographic metadata, record IDs, sizes, and duplicate IDs before replacement.
- Service worker caches only same-origin GET application resources. It has no health-data endpoint to cache.
- GitHub Actions receives read-only repository contents and only the minimum Pages/OIDC write permissions required for deployment.

## Threat-model limitations
This design protects data at rest from someone who obtains browser storage or an encrypted backup without the passphrase. It does not protect plaintext while the vault is unlocked from:
- a compromised iPhone / malicious OS-level software;
- malicious browser extensions or injected scripts;
- a hostile replacement of the hosted application code;
- shoulder surfing or an unlocked device in another person's hands.

Because a static web host can replace JavaScript, protect the repository with strong authentication, branch protection, reviewed changes, and dependency-free builds. For higher assurance, pin deployments to reviewed commits and consider a host that supports strict HTTP security headers.

## Cryptographic upgrade path
Argon2id is preferred for password-based key derivation when a well-audited implementation is available. This zero-dependency build uses Web Crypto PBKDF2 to avoid shipping third-party/WASM cryptography. A future schema version can add Argon2id and re-encrypt the vault after successful unlock.
