import crypto from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";

import { KDF_PARAMS, capsuleFingerprint, createCapsule, isLocked, openCapsule, unlockRemainingMs } from "../src/vault.js";

test("createCapsule returns expected cryptographic envelope fields", () => {
  const unlockAt = "2030-01-01T00:00:00.000Z";
  const capsule = createCapsule({ title: "hello", body: "future" }, "strongpass", unlockAt, Date.parse("2029-01-01T00:00:00.000Z"));

  assert.equal(capsule.algorithm, "aes-256-gcm");
  assert.equal(capsule.version, 3);
  assert.deepEqual(capsule.kdfParams, { N: 131072, r: 8, p: 1 });
  assert.equal(typeof capsule.salt, "string");
  assert.equal(typeof capsule.ciphertext, "string");
  assert.equal(capsule.unlockAt, unlockAt);
});

test("openCapsule decrypts payload after unlock time", () => {
  const now = Date.parse("2029-01-01T00:00:00.000Z");
  const unlockAt = "2029-01-03T00:00:00.000Z";
  const capsule = createCapsule({ title: "A", body: "B" }, "strongpass", unlockAt, now);

  const unlocked = openCapsule(capsule, "strongpass", Date.parse("2029-01-03T00:00:01.000Z"));
  assert.deepEqual(unlocked, { title: "A", body: "B" });
});

test("openCapsule throws while locked", () => {
  const now = Date.parse("2029-01-01T00:00:00.000Z");
  const unlockAt = "2029-01-02T00:00:00.000Z";
  const capsule = createCapsule({ title: "A" }, "strongpass", unlockAt, now);

  assert.throws(() => openCapsule(capsule, "strongpass", now), /CapsuleLocked/);
});

test("openCapsule fails with wrong passphrase", () => {
  const now = Date.parse("2029-01-01T00:00:00.000Z");
  const unlockAt = "2029-01-02T00:00:00.000Z";
  const capsule = createCapsule({ title: "A" }, "strongpass", unlockAt, now);

  assert.throws(() => openCapsule(capsule, "wrong-pass", Date.parse("2029-01-02T00:00:01.000Z")));
});

test("isLocked and unlockRemainingMs report lock status", () => {
  const now = Date.parse("2029-01-01T00:00:00.000Z");
  const unlockAt = "2029-01-01T01:00:00.000Z";
  const capsule = createCapsule({ title: "A" }, "strongpass", unlockAt, now);

  assert.equal(isLocked(capsule, now), true);
  assert.equal(unlockRemainingMs(capsule, now), 3600000);
});

test("openCapsule rejects capsules with tampered unlockAt metadata", () => {
  const now = Date.parse("2029-01-01T00:00:00.000Z");
  const unlockAt = "2029-01-02T00:00:00.000Z";
  const capsule = createCapsule({ title: "A" }, "strongpass", unlockAt, now);

  capsule.unlockAt = "2030-01-01T00:00:00.000Z";
  assert.throws(() => openCapsule(capsule, "strongpass", Date.parse("2030-01-01T00:00:01.000Z")));
});

test("capsuleFingerprint is deterministic for same capsule", () => {
  const now = Date.parse("2029-01-01T00:00:00.000Z");
  const capsule = createCapsule({ title: "A" }, "strongpass", "2029-01-02T00:00:00.000Z", now);

  const first = capsuleFingerprint(capsule);
  const second = capsuleFingerprint(capsule);
  assert.equal(first, second);
  assert.equal(first.length, 16);
});

// Seals a capsule exactly the way version 2 did: Node's default scrypt cost
// and no KDF parameters in the AAD.
function legacyV2Capsule(payload, passphrase, unlockAt, createdAt) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(passphrase, salt, 32);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(`v=2|alg=aes-256-gcm|unlockAt=${unlockAt}|createdAt=${createdAt}`, "utf8"));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload), "utf8"), cipher.final()]);
  return {
    version: 2, kdf: "scrypt", algorithm: "aes-256-gcm", unlockAt, createdAt,
    salt: salt.toString("base64"), iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"), ciphertext: ciphertext.toString("base64")
  };
}

test("version 2 capsules sealed at the old scrypt cost still open", () => {
  const capsule = legacyV2Capsule({ note: "old" }, "strongpass", "2029-01-02T00:00:00.000Z", "2029-01-01T00:00:00.000Z");
  assert.deepEqual(openCapsule(capsule, "strongpass", Date.parse("2029-01-03T00:00:00.000Z")), { note: "old" });
});

test("the KDF cost is bound into the AAD, so editing it breaks the seal", () => {
  const now = Date.parse("2029-01-01T00:00:00.000Z");
  const capsule = createCapsule({ title: "A" }, "strongpass", "2029-01-02T00:00:00.000Z", now);
  capsule.kdfParams = { ...KDF_PARAMS, p: 2 };
  assert.throws(() => openCapsule(capsule, "strongpass", Date.parse("2029-01-03T00:00:00.000Z")));
});

test("a capsule demanding an absurd scrypt cost is refused before deriving", () => {
  const now = Date.parse("2029-01-01T00:00:00.000Z");
  const capsule = createCapsule({ title: "A" }, "strongpass", "2029-01-02T00:00:00.000Z", now);
  const later = Date.parse("2029-01-03T00:00:00.000Z");
  assert.throws(() => openCapsule({ ...capsule, kdfParams: { N: 2 ** 30, r: 8, p: 1 } }, "strongpass", later), /CapsuleKdfTooExpensive/);
  assert.throws(() => openCapsule({ ...capsule, kdfParams: { N: 1000, r: 8, p: 1 } }, "strongpass", later), /CapsuleInvalidKdfParams/);
  assert.throws(() => openCapsule({ ...capsule, kdfParams: undefined }, "strongpass", later), /CapsuleInvalidKdfParams/);
});
