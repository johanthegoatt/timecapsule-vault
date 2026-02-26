# TimeCapsule Vault

## Description
TimeCapsule Vault is a local backend utility for encrypting notes and unlocking them only after a specific timestamp.

## Features
- AES-256-GCM encrypted payload storage
- Passphrase-derived key protection via `scrypt`
- Metadata integrity binding (unlock timestamp tampering is detected)
- Time lock enforcement with unlock countdown support
- CLI for creating, inspecting, and opening capsules (inline or file-based)
- Zero external APIs or cloud dependencies

## Run
```bash
cd timecapsule-vault
npm start -- create "Letter" "Open me later" "2030-01-01T00:00:00.000Z" "strongpass"
npm start -- inspect '{"version":2,"algorithm":"aes-256-gcm","unlockAt":"2030-01-01T00:00:00.000Z","createdAt":"2029-01-01T00:00:00.000Z","salt":"...","iv":"...","tag":"...","ciphertext":"..."}'
```

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
