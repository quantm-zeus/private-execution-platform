import assert from "node:assert/strict";
import { test } from "node:test";

import {
  UnlockError,
  asUnlockError,
  isUnlockError,
  recoveryFor,
  type UnlockReason,
  type UnlockStage,
} from "./unlock-stages.ts";

const STAGES: UnlockStage[] = [
  "U1_WASM",
  "U2_ENROLL",
  "U3_GRANT",
  "U4_TRANSPORT",
  "U5_ARTIFACT",
  "U6_PACKAGE",
  "U7_BOOT",
];

test("every stage has recovery guidance with a next action", () => {
  for (const stage of STAGES) {
    const recovery = recoveryFor(stage, "unknown");
    assert.equal(typeof recovery.stageLabel, "string");
    assert.ok(recovery.stageLabel.length > 0, `${stage} has a label`);
    assert.ok(recovery.title.length > 0, `${stage} has a title`);
    assert.ok(recovery.detail.length > 0, `${stage} has guidance`);
    assert.ok(
      ["error", "warning"].includes(recovery.severity),
      `${stage} has a severity`,
    );
    assert.ok(
      [
        "reload",
        "retry",
        "reenter_recovery",
        "resume_authentication",
        "rollback_release",
        "contact_operator",
      ].includes(recovery.action),
      `${stage} has an action`,
    );
  }
});

test("compatibility failures point at recovery, not blind retry", () => {
  const mismatch = recoveryFor("U5_ARTIFACT", "workspace_key_mismatch");
  assert.equal(mismatch.action, "contact_operator");
  const incompatible = recoveryFor("U5_ARTIFACT", "artifact_incompatible");
  assert.equal(incompatible.action, "contact_operator");
  const packageFailure = recoveryFor("U6_PACKAGE", "package_invalid");
  assert.equal(packageFailure.action, "rollback_release");
  const enrollment = recoveryFor("U2_ENROLL", "enrollment_conflict");
  assert.equal(enrollment.action, "reenter_recovery");
  const expired = recoveryFor("U2_ENROLL", "session_expired");
  assert.equal(expired.action, "resume_authentication");
});

test("unlock errors are generic and carry only a stage and reason", () => {
  const secret = "super-secret-recovery-code";
  const error = new UnlockError("U5_ARTIFACT", "artifact_decrypt_failed");
  assert.equal(error.message, "workspace unlock failed");
  assert.ok(!error.message.includes(secret));
  assert.equal(error.stage, "U5_ARTIFACT");
  assert.equal(error.reason, "artifact_decrypt_failed");
  assert.equal(error.name, "UnlockError");
});

test("foreign errors never leak their message through classification", () => {
  const foreign = new Error("secret-path-/home/operator/keys.bin");
  const classified = asUnlockError(foreign, "U4_TRANSPORT", "transport_rejected");
  assert.equal(classified.stage, "U4_TRANSPORT");
  assert.equal(classified.reason, "transport_rejected");
  assert.ok(!classified.message.includes("keys.bin"));
  assert.ok(!("cause" in classified));
});

test("asUnlockError preserves an already-classified error", () => {
  const original = new UnlockError("U6_PACKAGE", "package_invalid");
  const classified = asUnlockError(original, "U7_BOOT", "boot_failed");
  assert.equal(classified, original);
  assert.ok(isUnlockError(classified));
});

test("every reason maps without throwing", () => {
  const reasons: UnlockReason[] = [
    "wasm_unavailable",
    "invalid_secret",
    "invalid_kid",
    "descriptor_invalid",
    "protocol_incompatible",
    "workspace_key_mismatch",
    "session_expired",
    "enrollment_required",
    "enrollment_conflict",
    "enrollment_rejected",
    "grant_invalid",
    "grant_rejected",
    "transport_rejected",
    "artifact_incompatible",
    "artifact_decrypt_failed",
    "package_invalid",
    "boot_failed",
    "handoff_unavailable",
    "unknown",
  ];
  for (const stage of STAGES) {
    for (const reason of reasons) {
      const recovery = recoveryFor(stage, reason);
      assert.ok(recovery.title.length > 0);
    }
  }
});
