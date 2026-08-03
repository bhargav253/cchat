import assert from "node:assert/strict";
import test from "node:test";
import { BalancedAuthorization } from "./policy.ts";

test("balanced sessions expire after fifteen minutes", () => {
  const policy = new BalancedAuthorization();
  const expiresAt = policy.unlock(1_000);
  assert.equal(expiresAt, 901_000);
  assert.equal(policy.isUnlocked(900_999), true);
  assert.equal(policy.isUnlocked(901_001), false);
  assert.doesNotThrow(() => policy.requireSession(900_999));
  assert.throws(() => policy.requireSession(901_001), /expired/);
});

test("approval authorization is exact, short-lived, and single-use", () => {
  const policy = new BalancedAuthorization();
  policy.unlock(1_000);
  policy.authorizeApproval("digest_A", 2_000);
  assert.throws(() => policy.consumeApproval("digest_B", 2_001), /Fresh Face ID/);
  assert.doesNotThrow(() => policy.consumeApproval("digest_A", 61_999));
  assert.throws(() => policy.consumeApproval("digest_A", 62_000), /Fresh Face ID/);
  policy.authorizeApproval("digest_C", 3_000);
  assert.throws(() => policy.consumeApproval("digest_C", 63_001), /Fresh Face ID/);
});
