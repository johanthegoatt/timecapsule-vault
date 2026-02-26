import fs from "node:fs";
import path from "node:path";

import { capsuleFingerprint, createCapsule, isLocked, openCapsule, unlockRemainingMs } from "./vault.js";

function printUsage() {
  console.log("Usage:");
  console.log("  node src/cli.js create <title> <body> <unlockAtISO> <passphrase>");
  console.log("  node src/cli.js open <capsuleJson> <passphrase> [nowISO]");
  console.log("  node src/cli.js create-file <payloadJsonPath> <unlockAtISO> <passphrase> <outputPath>");
  console.log("  node src/cli.js open-file <capsuleJsonPath> <passphrase> [nowISO]");
  console.log("  node src/cli.js inspect <capsuleJson>");
}

function createCommand(args) {
  const [title, body, unlockAt, passphrase] = args;
  if (!title || !body || !unlockAt || !passphrase) {
    throw new Error("Missing arguments for create.");
  }

  const capsule = createCapsule({ title, body }, passphrase, unlockAt);
  console.log(JSON.stringify(capsule, null, 2));
}

function createFileCommand(args) {
  const [payloadPath, unlockAt, passphrase, outputPath] = args;
  if (!payloadPath || !unlockAt || !passphrase || !outputPath) {
    throw new Error("Missing arguments for create-file.");
  }

  const inputAbsolute = path.resolve(process.cwd(), payloadPath);
  const outputAbsolute = path.resolve(process.cwd(), outputPath);
  const payload = JSON.parse(fs.readFileSync(inputAbsolute, "utf8"));
  const capsule = createCapsule(payload, passphrase, unlockAt);
  fs.writeFileSync(outputAbsolute, `${JSON.stringify(capsule, null, 2)}\n`, "utf8");
  console.log(`Capsule written to ${outputPath}`);
}

function openCommand(args) {
  const [capsuleJson, passphrase, nowISO] = args;
  if (!capsuleJson || !passphrase) {
    throw new Error("Missing arguments for open.");
  }

  const capsule = JSON.parse(capsuleJson);
  const nowMs = nowISO ? Date.parse(nowISO) : Date.now();

  if (isLocked(capsule, nowMs)) {
    const remainingSeconds = Math.ceil(unlockRemainingMs(capsule, nowMs) / 1000);
    console.log(`Capsule is still locked. Try again in ~${remainingSeconds} second(s).`);
    return;
  }

  const payload = openCapsule(capsule, passphrase, nowMs);
  console.log(JSON.stringify(payload, null, 2));
}

function openFileCommand(args) {
  const [capsulePath, passphrase, nowISO] = args;
  if (!capsulePath || !passphrase) {
    throw new Error("Missing arguments for open-file.");
  }

  const capsuleAbsolute = path.resolve(process.cwd(), capsulePath);
  const capsule = JSON.parse(fs.readFileSync(capsuleAbsolute, "utf8"));
  const nowMs = nowISO ? Date.parse(nowISO) : Date.now();

  if (isLocked(capsule, nowMs)) {
    const remainingSeconds = Math.ceil(unlockRemainingMs(capsule, nowMs) / 1000);
    console.log(`Capsule is still locked. Try again in ~${remainingSeconds} second(s).`);
    return;
  }

  const payload = openCapsule(capsule, passphrase, nowMs);
  console.log(JSON.stringify(payload, null, 2));
}

function inspectCommand(args) {
  const [capsuleJson] = args;
  if (!capsuleJson) {
    throw new Error("Missing arguments for inspect.");
  }

  const capsule = JSON.parse(capsuleJson);
  const nowMs = Date.now();
  console.log(
    JSON.stringify(
      {
        version: capsule.version,
        algorithm: capsule.algorithm,
        unlockAt: capsule.unlockAt,
        createdAt: capsule.createdAt,
        locked: isLocked(capsule, nowMs),
        remainingMs: unlockRemainingMs(capsule, nowMs),
        fingerprint: capsuleFingerprint(capsule)
      },
      null,
      2
    )
  );
}

function main() {
  const [command, ...args] = process.argv.slice(2);
  if (!command) {
    printUsage();
    return;
  }

  if (command === "create") {
    createCommand(args);
    return;
  }

  if (command === "open") {
    openCommand(args);
    return;
  }

  if (command === "create-file") {
    createFileCommand(args);
    return;
  }

  if (command === "open-file") {
    openFileCommand(args);
    return;
  }

  if (command === "inspect") {
    inspectCommand(args);
    return;
  }

  printUsage();
}

try {
  main();
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
