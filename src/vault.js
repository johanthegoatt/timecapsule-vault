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

function deriveKey(passphrase, salt) {
  return crypto.scryptSync(passphrase, salt, KEY_SIZE);
}

function aadString(version, algorithm, unlockAt, createdAt) {
  return `v=${version}|alg=${algorithm}|unlockAt=${unlockAt}|createdAt=${createdAt}`;
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
  const key = deriveKey(passphrase, salt);
  const createdAt = new Date(nowMs).toISOString();
  const version = 2;
  const aad = Buffer.from(aadString(version, ALGORITHM, unlockAt, createdAt), "utf8");

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  cipher.setAAD(aad);
  const plaintext = JSON.stringify(payload);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    version,
    kdf: "scrypt",
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
  const key = deriveKey(passphrase, salt);

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  if (Number(capsule.version || 1) >= 2) {
    const aad = Buffer.from(
      aadString(Number(capsule.version || 2), capsule.algorithm, capsule.unlockAt, capsule.createdAt),
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
