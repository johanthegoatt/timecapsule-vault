# TimeCapsule Vault

## Description
TimeCapsule Vault is a local backend utility for encrypting notes and unlocking them only after a specific timestamp.

## Features
- AES-256-GCM encrypted payload storage
- Passphrase-derived key via `scrypt` at N=2^17, r=8, p=1, the first row of the OWASP Password Storage Cheat Sheet, with the cost stored in the capsule and bound into the AAD
- Capsules naming a cost above 1 GiB of scrypt memory are refused before any work, so a hostile file cannot stall the opener
- Metadata integrity binding (unlock timestamp tampering is detected)
- Time lock enforcement with unlock countdown support
- CLI for creating, inspecting, and opening capsules (inline or file-based)
- Zero external APIs or cloud dependencies

## Run
```bash
cd timecapsule-vault
npm start -- create "Letter" "Open me later" "2030-01-01T00:00:00.000Z" "strongpass"
npm start -- inspect '{"version":3,"kdf":"scrypt","kdfParams":{"N":131072,"r":8,"p":1},"algorithm":"aes-256-gcm","unlockAt":"2030-01-01T00:00:00.000Z","createdAt":"2029-01-01T00:00:00.000Z","salt":"...","iv":"...","tag":"...","ciphertext":"..."}'
```

## Capsule versions
| version | scrypt cost | AAD binds |
|---|---|---|
| 2 | N=2^14 (Node's default) | version, algorithm, unlockAt, createdAt |
| 3 | N=2^17, stored in `kdfParams` | the above plus the KDF parameters |

Version 2 capsules still open. A capsule is a file that can be copied and attacked offline, so each guess costing about eight times more work at N=2^17 is the main defence for a weak passphrase. On a laptop one derivation takes about 0.3s.

## Test
```bash
cd timecapsule-vault
npm test
```

## Project Structure
```text
timecapsule-vault/
  src/
    cli.js
    vault.js
  tests/
    vault.test.js
  package.json
  README.md
```
