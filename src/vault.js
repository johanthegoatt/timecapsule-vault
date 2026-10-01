import crypto from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const KEY_SIZE = 32;

function toBase64(value) {
  return Buffer.from(value).toString("base64");
}

function fromBase64(value) {
  return Buffer.from(value, "base64");
}

function parseUnlockAt(unlockAt) {
  const timestamp = Date.parse(unlockAt);
  if (!Number.isFinite(timestamp)) {
    throw new Error("Invalid unlockAt timestamp.");
  }
  return timestamp;
}

// OWASP Password Storage Cheat Sheet, first scrypt row: N=2^17, r=8, p=1
// (128 MiB). Node's own default is N=2^14, an eighth of the work, which is
// what capsules before version 3 were sealed with. A capsule is a file an
// attacker can copy and brute-force offline for as long as they like, so
// the cost per guess is the whole defence of a weak passphrase.
export const KDF_PARAMS = Object.freeze({ N: 2 ** 17, r: 8, p: 1 });
const LEGACY_KDF_PARAMS = Object.freeze({ N: 2 ** 14, r: 8, p: 1 });

// A capsule names its own cost, so a hostile one could ask for N=2^30 and
// stall or crash whoever opens it. Anything above this ceiling is refused.
const MAX_KDF_MEMORY = 1024 * 1024 * 1024;

function kdfMemory({ N, r, p }) {
  return 128 * N * r * p;
}

function readKdfParams(capsule) {
  if (Number(capsule.version || 1) < 3) return LEGACY_KDF_PARAMS;
  const params = capsule.kdfParams;
  const valid =
    params &&
    [params.N, params.r, params.p].every(Number.isSafeInteger) &&
    params.N > 1 && (params.N & (params.N - 1)) === 0 &&
    params.r > 0 && params.p > 0;
  if (!valid) throw new Error("CapsuleInvalidKdfParams");
  if (kdfMemory(params) > MAX_KDF_MEMORY) throw new Error("CapsuleKdfTooExpensive");
  return { N: params.N, r: params.r, p: params.p };
}

function deriveKey(passphrase, salt, params) {
  // Node refuses anything over maxmem (32 MiB by default), so size it to the
  // parameters with headroom for its own bookkeeping.
  return crypto.scryptSync(passphrase, salt, KEY_SIZE, { ...params, maxmem: 2 * kdfMemory(params) });
}

function aadString(version, algorithm, unlockAt, createdAt, params) {
  const base = `v=${version}|alg=${algorithm}|unlockAt=${unlockAt}|createdAt=${createdAt}`;
  return version >= 3 ? `${base}|kdf=scrypt:N=${params.N},r=${params.r},p=${params.p}` : base;
}

function ensureCapsuleShape(capsule) {
  const required = ["algorithm", "unlockAt", "createdAt", "salt", "iv", "tag", "ciphertext"];
  for (const key of required) {
    if (!capsule || typeof capsule[key] !== "string" || capsule[key].length === 0) {
      throw new Error(`CapsuleMissingField:${key}`);
    }
  }
}

export function createCapsule(payload, passphrase, unlockAt, nowMs = Date.now()) {
  if (!passphrase || String(passphrase).length < 8) {
    throw new Error("Passphrase must be at least 8 characters.");
  }

  const unlockAtMs = parseUnlockAt(unlockAt);
  if (unlockAtMs <= nowMs) {
    throw new Error("unlockAt must be in the future.");
  }

  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = deriveKey(passphrase, salt, KDF_PARAMS);
  const createdAt = new Date(nowMs).toISOString();
  const version = 3;
  const aad = Buffer.from(aadString(version, ALGORITHM, unlockAt, createdAt, KDF_PARAMS), "utf8");

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  cipher.setAAD(aad);
  const plaintext = JSON.stringify(payload);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    version,
    kdf: "scrypt",
    kdfParams: { ...KDF_PARAMS },
    algorithm: ALGORITHM,
    unlockAt,
    createdAt,
    salt: toBase64(salt),
    iv: toBase64(iv),
    tag: toBase64(tag),
    ciphertext: toBase64(encrypted)
  };
}

export function openCapsule(capsule, passphrase, nowMs = Date.now()) {
  ensureCapsuleShape(capsule);
  const unlockAtMs = parseUnlockAt(capsule.unlockAt);
  if (nowMs < unlockAtMs) {
    throw new Error("CapsuleLocked");
  }

  const salt = fromBase64(capsule.salt);
  const iv = fromBase64(capsule.iv);
  const tag = fromBase64(capsule.tag);
  const ciphertext = fromBase64(capsule.ciphertext);
  const params = readKdfParams(capsule);
  const key = deriveKey(passphrase, salt, params);

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  if (Number(capsule.version || 1) >= 2) {
    const aad = Buffer.from(
      aadString(Number(capsule.version || 2), capsule.algorithm, capsule.unlockAt, capsule.createdAt, params),
      "utf8"
    );
    decipher.setAAD(aad);
  }
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  return JSON.parse(decrypted);
}

export function isLocked(capsule, nowMs = Date.now()) {
  return nowMs < parseUnlockAt(capsule.unlockAt);
}

export function unlockRemainingMs(capsule, nowMs = Date.now()) {
  return Math.max(0, parseUnlockAt(capsule.unlockAt) - nowMs);
}

export function capsuleFingerprint(capsule) {
  ensureCapsuleShape(capsule);
  const digest = crypto
    .createHash("sha256")
    .update(`${capsule.ciphertext}:${capsule.salt}:${capsule.iv}:${capsule.tag}`)
    .digest("hex");
  return digest.slice(0, 16);
}
