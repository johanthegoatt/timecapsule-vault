import test from "node:test";
import assert from "node:assert/strict";

import { capsuleFingerprint, createCapsule, isLocked, openCapsule, unlockRemainingMs } from "../src/vault.js";

test("createCapsule returns expected cryptographic envelope fields", () => {
  const unlockAt = "2030-01-01T00:00:00.000Z";
  const capsule = createCapsule({ title: "hello", body: "future" }, "strongpass", unlockAt, Date.parse("2029-01-01T00:00:00.000Z"));

  assert.equal(capsule.algorithm, "aes-256-gcm");
  assert.equal(capsule.version, 2);
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
