import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { describe, it } from "node:test";
import sodium from "sodium-native";
import { hashPassword, verifyPassword } from "../index.js";

describe("PasswordService", () => {
  it("should hash and verify correct password (default)", async () => {
    const password = randomUUID();
    const hash = await hashPassword(password);
    const verifiedResult = await verifyPassword(hash, password);
    assert.equal(verifiedResult, true);
  });

  it("should hash and verify incorrect password  (default)", async () => {
    const password = randomUUID();
    const hash = await hashPassword(password);
    const verifiedResult = await verifyPassword(hash, `${password}1`);
    assert.equal(verifiedResult, false);
  });

  it("should hash and verify correct password (interactive)", async () => {
    const password = randomUUID();
    const hash = await hashPassword(password, { limit: "interactive" });
    const verifiedResult = await verifyPassword(hash, password);
    assert.equal(verifiedResult, true);
  });

  it("should hash and verify incorrect password  (interactive)", async () => {
    const password = randomUUID();
    const hash = await hashPassword(password, { limit: "interactive" });
    const verifiedResult = await verifyPassword(hash, `${password}1`);
    assert.equal(verifiedResult, false);
  });

  it("should hash and verify correct password (min)", async () => {
    const password = randomUUID();
    const hash = await hashPassword(password, { limit: "min" });
    const verifiedResult = await verifyPassword(hash, password);
    assert.equal(verifiedResult, true);
  });

  it("should hash and verify incorrect password  (min)", async () => {
    const password = randomUUID();
    const hash = await hashPassword(password, { limit: "min" });
    const verifiedResult = await verifyPassword(hash, `${password}1`);
    assert.equal(verifiedResult, false);
  });

  it("should hash and verify correct password (moderate)", async () => {
    const password = randomUUID();
    const hash = await hashPassword(password, { limit: "moderate" });
    const verifiedResult = await verifyPassword(hash, password);
    assert.equal(verifiedResult, true);
  });

  it("should hash and verify incorrect password  (moderate)", async () => {
    const password = randomUUID();
    const hash = await hashPassword(password, { limit: "moderate" });
    const verifiedResult = await verifyPassword(hash, `${password}1`);
    assert.equal(verifiedResult, false);
  });

  it("should hash and verify correct password (sensitive)", async () => {
    const password = randomUUID();
    const hash = await hashPassword(password, { limit: "sensitive" });
    const verifiedResult = await verifyPassword(hash, password);
    assert.equal(verifiedResult, true);
  });

  it("should hash and verify incorrect password  (sensitive)", async () => {
    const password = randomUUID();
    const hash = await hashPassword(password, { limit: "sensitive" });
    const verifiedResult = await verifyPassword(hash, `${password}1`);
    assert.equal(verifiedResult, false);
  });

  it("should hash and verify correct password (sensitive)", async () => {
    const password = randomUUID();
    const hash = await hashPassword(password, {
      memLimit: sodium.crypto_pwhash_MEMLIMIT_MIN,
      opsLimit: sodium.crypto_pwhash_OPSLIMIT_MIN
    });
    const verifiedResult = await verifyPassword(hash, password);
    assert.equal(verifiedResult, true);
  });

  it("should hash and verify incorrect password  (sensitive)", async () => {
    const password = randomUUID();
    const hash = await hashPassword(password, {
      memLimit: sodium.crypto_pwhash_MEMLIMIT_MIN,
      opsLimit: sodium.crypto_pwhash_OPSLIMIT_MIN
    });
    const verifiedResult = await verifyPassword(hash, `${password}1`);
    assert.equal(verifiedResult, false);
  });
});
