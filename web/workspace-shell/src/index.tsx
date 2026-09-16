import { render } from "solid-js/web";
import { createSignal, onMount, onCleanup, Show, For } from "solid-js";
import "./style.css";
import { defaultRuntime, loadWasm, toBase64 } from "./unlock-runtime";
import {
  authenticateWithPasskey,
  enrollPasskey,
  PasskeyAuthError,
} from "./passkey-auth";
import {
  fetchWorkspaceDescriptor,
  DescriptorError,
  type WorkspaceDescriptor,
} from "./descriptor";
import {
  RecoveryClientError,
  addRecoveryWrapper,
  beginRecoveryProof,
  bootstrapWorkspaceIdentity,
  fetchRecoveryWrappers,
  fetchWorkspaceIdentity,
  fromBase64 as recoveryFromBase64,
  revokeRecoveryWrapper,
  touchRecoveryWrapper,
  unwrapWithPrfOutput,
  type BootstrapWrapperInput,
  type RecoveryWrapperRecord,
  type WorkspaceIdentity,
} from "./recovery-client";
import { authenticateWithPrf } from "./recovery-passkey";
import {
  OFFLINE_RECOVERY_CREDENTIAL_B64,
  WORKSPACE_ROOT_KEY_SOURCE,
  WORKSPACE_ROOT_VERSION,
  decodeRecoveryCode,
  deriveWorkspaceRootFingerprint,
  deriveWorkspaceRootPublicKey,
  generateRecoveryCode,
  generateWorkspaceRootSecret,
  isOfflineRecoveryCredential,
  selectPasskeyUnlockWrappers,
  unwrapWorkspaceRootWithRecovery,
  wrapWorkspaceRootForRecovery,
  workspaceRootMatchesFingerprint,
} from "./workspace-root";
import { generateRecoverySalt, wrapRootKey } from "./recovery-wrapping";
import {
  isUnlockError,
  recoveryFor,
  type RecoveryAction,
  type UnlockRecovery,
  type UnlockStage,
} from "./unlock-stages";

type AuthState =
  | "checking"
  | "signed_out"
  | "authenticating"
  | "authenticated"
  | "unsupported";

/**
 * Initial-setup phases. `show_recovery` gates the workspace until the operator
 * confirms the one-time recovery code is saved.
 */
type SetupPhase = "unconfigured" | "preparing" | "show_recovery" | "done";

const ENROLLMENT_STATUS_URL = "/internal/auth/enrollment-status";
const SESSION_URL = "/internal/auth/session";

/** Ordered unlock stages, shown as an auditable security ledger. */
const STAGES: { id: UnlockStage; label: string }[] = [
  { id: "U1_WASM", label: "Crypto module" },
  { id: "U2_ENROLL", label: "Workspace identity" },
  { id: "U3_GRANT", label: "Artifact access" },
  { id: "U4_TRANSPORT", label: "Encrypted session" },
  { id: "U5_ARTIFACT", label: "Release compatibility" },
  { id: "U6_PACKAGE", label: "Release package" },
  { id: "U7_BOOT", label: "Workspace start" },
];

/** Textual status for one unlock stage, so progress is never color-only. */
function stageStatusText(current: UnlockStage | null, id: UnlockStage): string {
  if (current === null) return "";
  const currentIndex = STAGES.findIndex((s) => s.id === current);
  const index = STAGES.findIndex((s) => s.id === id);
  if (index < currentIndex) return "complete";
  if (index === currentIndex) return "in progress";
  return "pending";
}

/**
 * Recoverable actions that have a concrete control. `contact_operator` and
 * `rollback_release` are handled by the operator, so they stay text-only.
 */
const RECOVERY_ACTION_LABELS: Partial<Record<RecoveryAction, string>> = {
  resume_authentication: "Verify passkey again",
  reload: "Reload page",
  retry: "Re-enter code and retry",
  reenter_recovery: "Re-enter recovery code",
};

function App() {
  const [status, setStatus] = createSignal("Security gateway ready.");
  const [authState, setAuthState] = createSignal<AuthState>("checking");
  const [authMessage, setAuthMessage] = createSignal(
    "Checking whether an operator session already exists...",
  );
  const [enrollmentOpen, setEnrollmentOpen] = createSignal(false);
  const [enrollSecret, setEnrollSecret] = createSignal("");
  const [isEnrolling, setIsEnrolling] = createSignal(false);
  const [enrollInvalid, setEnrollInvalid] = createSignal(false);

  const [descriptor, setDescriptor] = createSignal<WorkspaceDescriptor | null>(null);
  const [descriptorError, setDescriptorError] = createSignal("");
  const [descriptorLoading, setDescriptorLoading] = createSignal(false);

  const [identity, setIdentity] = createSignal<WorkspaceIdentity | null>(null);
  const [identityError, setIdentityError] = createSignal("");
  const [wrappers, setWrappers] = createSignal<RecoveryWrapperRecord[]>([]);
  const [setupPhase, setSetupPhase] = createSignal<SetupPhase>("unconfigured");
  const [setupRecoveryCode, setSetupRecoveryCode] = createSignal("");
  const [setupError, setSetupError] = createSignal("");
  const [savedConfirmed, setSavedConfirmed] = createSignal(false);

  const [isUnlocking, setIsUnlocking] = createSignal(false);
  const [unlockStage, setUnlockStage] = createSignal<UnlockStage | null>(null);
  const [unlockFailure, setUnlockFailure] = createSignal<UnlockRecovery | null>(null);
  const [isUnlocked, setIsUnlocked] = createSignal(false);
  const [payloadUrl, setPayloadUrl] = createSignal("");
  const [autoUnlockRan, setAutoUnlockRan] = createSignal(false);

  const [cryptoReady, setCryptoReady] = createSignal(false);
  const [cryptoError, setCryptoError] = createSignal(false);

  const [troubleOpen, setTroubleOpen] = createSignal(false);
  const [recoveryCodeInput, setRecoveryCodeInput] = createSignal("");
  const [recoveryInvalid, setRecoveryInvalid] = createSignal(false);
  const [recoveryMessage, setRecoveryMessage] = createSignal("");
  const [recoveryBusy, setRecoveryBusy] = createSignal(false);

  const [deviceLabel, setDeviceLabel] = createSignal("This device");
  const [addRecoveryCode, setAddRecoveryCode] = createSignal("");
  const [addRecoveryInvalid, setAddRecoveryInvalid] = createSignal(false);
  const [securityMessage, setSecurityMessage] = createSignal("");

  let frame: HTMLIFrameElement | undefined;
  let recoveryInput: HTMLInputElement | undefined;
  let alertRef: HTMLDivElement | undefined;

  // Same-document channel with the decrypted payload. Only messages from our
  // own frame and origin are honoured, and the ready ping must echo the
  // per-unlock handoff token injected into the payload document.
  const onPayloadMessage = (event: MessageEvent) => {
    if (!frame || event.source !== frame.contentWindow) return;
    if (event.origin !== window.location.origin) return;
    const data = event.data as { type?: unknown; handoff?: unknown } | null;
    if (!data || typeof data !== "object") return;
    if (data.type === "evergreen:lock-request") {
      handleLock();
    } else if (data.type === "evergreen:workspace-ready") {
      setStatus("Private workspace ready.");
      deliverSessionKeys(data.handoff);
    }
  };

  const deliverSessionKeys = (handoff: unknown) => {
    const target = frame?.contentWindow;
    if (!target) return;
    const keys = defaultRuntime.takeSessionKeysForHandoff(handoff);
    if (!keys) return;
    try {
      target.postMessage(
        {
          type: "evergreen:session-key",
          kid: keys.kid,
          s2cKeyB64: keys.s2cKeyB64,
          c2sKeyB64: keys.c2sKeyB64,
        },
        window.location.origin,
      );
    } catch {
      // Best effort. Without the handoff the payload stays explicitly offline.
    }
  };

  const loadDescriptor = async (): Promise<boolean> => {
    setDescriptorError("");
    setDescriptor(null);
    setDescriptorLoading(true);
    try {
      const value = await fetchWorkspaceDescriptor();
      setDescriptor(value);
      return true;
    } catch (error) {
      if (error instanceof DescriptorError && error.code === "descriptor_unauthorized") {
        setAuthState("signed_out");
        setAuthMessage(
          "Operator session required. Open the private workspace to verify your passkey.",
        );
        return false;
      }
      setDescriptorError(
        "The server did not publish a usable workspace release descriptor. Retry, or contact the operator.",
      );
      return false;
    } finally {
      setDescriptorLoading(false);
    }
  };

  const loadIdentity = async (): Promise<WorkspaceIdentity | null> => {
    setIdentityError("");
    try {
      const value = await fetchWorkspaceIdentity();
      setIdentity(value);
      return value;
    } catch {
      // A closed identity surface means this workspace cannot be set up or
      // unlocked with the stable root; fail closed rather than silently fall
      // back to the legacy release-bound path.
      setIdentity(null);
      setIdentityError(
        "The workspace identity service is unavailable. Retry, or contact the operator.",
      );
      return null;
    }
  };

  const loadWrappers = async (): Promise<RecoveryWrapperRecord[]> => {
    try {
      const value = await fetchRecoveryWrappers();
      setWrappers(value);
      return value;
    } catch {
      setWrappers([]);
      return [];
    }
  };

  /**
   * Copy the unlocked root into the runtime (which copies before its first
   * await) and zeroize the caller's buffer immediately.
   */
  const finishUnlock = async (
    root: Uint8Array,
    activeDescriptor: WorkspaceDescriptor,
  ): Promise<void> => {
    let unlockPromise: ReturnType<typeof defaultRuntime.unlock> | null = null;
    try {
      unlockPromise = defaultRuntime.unlock(root, activeDescriptor, {
        onStage: (stage) => setUnlockStage(stage),
      });
    } finally {
      root.fill(0);
    }
    // `unlock` copies the root synchronously before its first await, so the
    // caller's buffer is already zeroized. A synchronous throw propagates from
    // the assignment above and is handled by the caller.
    const result = await (unlockPromise as NonNullable<typeof unlockPromise>);
    setPayloadUrl(result.htmlUrl);
    setIsUnlocked(true);
    setStatus("Private workspace opened.");
    queueMicrotask(() => document.getElementById("workspace-region")?.focus());
  };

  /** Load everything a signed-in session needs, then auto-unlock if configured. */
  const refreshAccess = async () => {
    setAutoUnlockRan(false);
    // The durable workspace identity is independent of any release, so it is
    // loaded even when no descriptor/artifact is published yet: initial setup
    // must remain reachable on a clean deployment where no release exists.
    const loadedIdentity = await loadIdentity();
    if (!loadedIdentity) return;
    if (!loadedIdentity.configured) {
      if (setupPhase() !== "show_recovery") setSetupPhase("unconfigured");
      void loadDescriptor();
      return;
    }
    setSetupPhase("done");
    const descriptorOk = await loadDescriptor();
    const activeWrappers = await loadWrappers();
    if (!descriptorOk) return;
    void runAutoUnlock(loadedIdentity, activeWrappers);
  };

  const runAuthentication = async () => {
    setAuthState("authenticating");
    setAuthMessage("Waiting for your passkey...");
    setUnlockFailure(null);
    try {
      await authenticateWithPasskey();
      setAuthState("authenticated");
      setAuthMessage("Passkey verified.");
      await refreshAccess();
    } catch (error) {
      if (error instanceof PasskeyAuthError && error.code === "webauthn_unsupported") {
        setAuthState("unsupported");
        setAuthMessage("This browser does not support passkeys.");
        return;
      }
      setAuthState("signed_out");
      setAuthMessage("Passkey verification did not complete. Try again when ready.");
    }
  };

  /**
   * Normal path: a passkey with a usable PRF output unwraps the same stable
   * Workspace Root Secret, which is validated against the durable public
   * identity before it is used to decrypt the current release.
   */
  const runAutoUnlock = async (
    identityValue: WorkspaceIdentity,
    wrapperList: RecoveryWrapperRecord[],
  ) => {
    if (isUnlocking() || isUnlocked() || autoUnlockRan()) return;
    setAutoUnlockRan(true);
    const activeDescriptor = descriptor();
    if (!activeDescriptor || !identityValue.fingerprintB64) return;
    const active = selectPasskeyUnlockWrappers(wrapperList);
    if (active.length === 0) {
      setTroubleOpen(true);
      setStatus("No passkey unlock is registered for this workspace.");
      return;
    }
    setIsUnlocking(true);
    setUnlockFailure(null);
    setUnlockStage("U1_WASM");
    setStatus("Unlocking with your passkey...");
    let lastFailure: UnlockRecovery | null = null;
    try {
      for (const wrapper of active) {
        let salt: Uint8Array;
        try {
          salt = recoveryFromBase64(wrapper.salt_b64);
        } catch {
          continue;
        }
        let prfOutput: Uint8Array | null = null;
        let credentialIdB64 = "";
        try {
          const result = await authenticateWithPrf({
            allowCredentialB64: wrapper.credential_id_b64,
            prfSalt: salt,
          });
          prfOutput = result.prfOutput;
          credentialIdB64 = result.credentialIdB64;
        } catch {
          continue;
        }
        if (!prfOutput) continue;
        let root: Uint8Array | null = null;
        try {
          root = await unwrapWithPrfOutput(prfOutput, wrapper);
        } catch {
          continue;
        } finally {
          prfOutput.fill(0);
        }
        if (!root) continue;
        if (!(await workspaceRootMatchesFingerprint(root, identityValue.fingerprintB64))) {
          root.fill(0);
          continue;
        }
        try {
          await finishUnlock(root, activeDescriptor);
          // Best-effort last-used metadata; requires its own proof of possession.
          void beginRecoveryProof((sealed) =>
            defaultRuntime.decryptRecoveryChallenge(sealed),
          )
            .then((proof) =>
              touchRecoveryWrapper({
                challengeId: proof.challengeId,
                proofB64: proof.proofB64,
                credentialIdB64,
              }),
            )
            .catch(() => {});
          setTroubleOpen(false);
          setRecoveryMessage("");
          return;
        } catch (error) {
          defaultRuntime.lock();
          lastFailure = isUnlockError(error)
            ? recoveryFor(error.stage, error.reason)
            : recoveryFor("U7_BOOT", "unknown");
        }
      }
      setTroubleOpen(true);
      setRecoveryMessage(
        "Automatic passkey unlock was not available. Use your offline recovery code.",
      );
      if (lastFailure) setUnlockFailure(lastFailure);
      setStatus("Passkey unlock did not complete.");
    } finally {
      setUnlockStage(null);
      setIsUnlocking(false);
    }
  };

  /**
   * One-time initial setup. The browser generates the Workspace Root Secret and
   * a separate recovery code locally, derives the stable public identity, wraps
   * the root under a passkey-PRF wrapper and the recovery wrapper, and uploads
   * only the public key plus the opaque wrappers.
   */
  const runInitialSetup = async () => {
    if (setupPhase() === "preparing") return;
    setSetupPhase("preparing");
    setSetupError("");
    setStatus("Creating this workspace...");
    let root: Uint8Array | null = null;
    // Hoisted: if the create-once bootstrap response is lost we must still be
    // able to surface this code (the identity can never be recreated).
    let recoveryCode = "";
    try {
      root = generateWorkspaceRootSecret();
      const publicKey = await deriveWorkspaceRootPublicKey(root);
      recoveryCode = generateRecoveryCode();
      const recoveryBytes = decodeRecoveryCode(recoveryCode);
      let recoveryRecord;
      try {
        recoveryRecord = await wrapWorkspaceRootForRecovery(root, recoveryBytes);
      } finally {
        recoveryBytes.fill(0);
      }
      const bootstrapWrappers: BootstrapWrapperInput[] = [
        {
          credentialIdB64: OFFLINE_RECOVERY_CREDENTIAL_B64,
          label: "Offline recovery code",
          record: recoveryRecord,
        },
      ];
      // Attempt a passkey-PRF wrapper for automatic future unlock. An
      // authenticator without PRF is not fatal: the recovery code remains the
      // mandatory fallback.
      let prfAvailable = false;
      const salt = generateRecoverySalt();
      try {
        const assertion = await authenticateWithPrf({ prfSalt: salt });
        if (assertion.prfOutput) {
          const record = await wrapRootKey(
            assertion.prfOutput,
            root,
            salt,
            undefined,
            assertion.credentialIdB64,
            WORKSPACE_ROOT_KEY_SOURCE,
          );
          assertion.prfOutput.fill(0);
          prfAvailable = true;
          bootstrapWrappers.push({
            credentialIdB64: assertion.credentialIdB64,
            label: deviceLabel().trim() || "This device",
            record,
          });
        }
      } catch {
        // PRF unavailable: keep the recovery wrapper only.
      }
      const created = await bootstrapWorkspaceIdentity({
        version: WORKSPACE_ROOT_VERSION,
        publicKeyB64: toBase64(publicKey),
        wrappers: bootstrapWrappers,
      });
      setIdentity(created);
      // Reveal and gate the recovery code BEFORE attempting to decrypt any
      // release. A migration/unlock failure must never leave the bootstrap
      // complete (create-once) with the recovery code unseen.
      setSetupRecoveryCode(recoveryCode);
      setSavedConfirmed(false);
      setSetupPhase("show_recovery");
      const activeDescriptor = descriptor();
      if (!activeDescriptor) {
        setStatus(
          "Workspace created. Save your recovery code; no release is published yet.",
        );
        return;
      }
      try {
        await finishUnlock(root, activeDescriptor);
        root = null;
        setStatus(
          prfAvailable
            ? "Workspace created. Save your recovery code."
            : "Workspace created. Save your recovery code; this authenticator has no passkey unlock.",
        );
      } catch {
        // The current release may not yet be sealed to the new stable key (the
        // documented one-time migration step). The recovery code is already
        // shown and gated, so this is recoverable once a matching release ships.
        defaultRuntime.lock();
        setStatus(
          "Workspace created. Save your recovery code; the current release is not sealed to this workspace yet.",
        );
      }
    } catch (error) {
      // The create-once bootstrap may have committed even when the response was
      // lost (a network drop or post-commit 5xx). Re-read the durable identity:
      // if it now matches the root we generated, surface the recovery code
      // instead of abandoning it, because the identity can never be recreated.
      let recovered = false;
      if (recoveryCode && root) {
        const current = await loadIdentity();
        if (
          current?.configured &&
          (await workspaceRootMatchesFingerprint(root, current.fingerprintB64))
        ) {
          setSetupRecoveryCode(recoveryCode);
          setSavedConfirmed(false);
          setSetupPhase("show_recovery");
          setStatus(
            "Workspace created. Save your recovery code; the server response was interrupted.",
          );
          recovered = true;
        }
      }
      if (!recovered) {
        setSetupError(
          error instanceof RecoveryClientError && error.code === "recovery_conflict"
            ? "This workspace is already set up. Reload to unlock it."
            : "Workspace setup did not complete. Retry, or contact the operator.",
        );
        setSetupPhase("unconfigured");
        setStatus("Workspace setup failed.");
      }
    } finally {
      if (root) root.fill(0);
    }
  };

  const confirmRecoverySaved = () => {
    // Drop the recovery code from every reactive/UI reference before revealing
    // the workspace. It is never persisted and never sent to the server.
    setSetupRecoveryCode("");
    setSavedConfirmed(false);
    setSetupPhase("done");
    setStatus("Private workspace ready.");
  };

  const runRecoveryAction = (action: RecoveryAction) => {
    switch (action) {
      case "resume_authentication":
        void runAuthentication();
        return;
      case "reload":
        window.location.reload();
        return;
      case "retry":
      case "reenter_recovery":
        setRecoveryCodeInput("");
        setTroubleOpen(true);
        if (recoveryInput) {
          recoveryInput.value = "";
          recoveryInput.focus();
        }
        return;
      default:
        return;
    }
  };

  const checkExistingSession = async () => {
    try {
      const response = await fetch(SESSION_URL, {
        method: "GET",
        credentials: "same-origin",
        redirect: "error",
      });
      if (response.status === 204) {
        setAuthState("authenticated");
        setAuthMessage("Existing operator session restored.");
        await refreshAccess();
        return;
      }
    } catch {
      // Fall through to the signed-out gateway.
    }
    setAuthState("signed_out");
    setAuthMessage("Verify your passkey to open the private workspace.");
  };

  const loadEnrollmentStatus = async () => {
    try {
      const response = await fetch(ENROLLMENT_STATUS_URL, {
        credentials: "same-origin",
        redirect: "error",
        headers: { Accept: "application/json" },
      });
      if (!response.ok) return;
      const body = (await response.json()) as { enrollment_open?: unknown };
      setEnrollmentOpen(body.enrollment_open === true);
    } catch {
      setEnrollmentOpen(false);
    }
  };

  const handleEnroll = async (e: Event) => {
    e.preventDefault();
    if (isEnrolling()) return;
    setEnrollInvalid(false);
    const secretValue = enrollSecret().trim();
    setEnrollSecret("");
    if (!secretValue) {
      setEnrollInvalid(true);
      setAuthMessage("Operator enrollment secret required.");
      return;
    }
    setIsEnrolling(true);
    setAuthMessage("Enrolling passkey...");
    try {
      await enrollPasskey(secretValue);
      setEnrollInvalid(false);
      await runAuthentication();
    } catch (error) {
      setEnrollInvalid(true);
      setAuthMessage(
        error instanceof PasskeyAuthError && error.code === "enrollment_unavailable"
          ? "Passkey enrollment is not open."
          : "Passkey enrollment failed.",
      );
    } finally {
      setIsEnrolling(false);
    }
  };

  onMount(async () => {
    window.addEventListener("message", onPayloadMessage);
    try {
      await loadWasm();
      setCryptoReady(true);
      setCryptoError(false);
      setStatus("Crypto boundary ready.");
    } catch {
      setCryptoError(true);
      setStatus("Crypto boundary unavailable in this browser.");
    }
    await loadEnrollmentStatus();
    await checkExistingSession();
  });

  const retryCrypto = async () => {
    setCryptoError(false);
    setStatus("Loading the crypto boundary...");
    try {
      await loadWasm();
      setCryptoReady(true);
      setCryptoError(false);
      setStatus("Crypto boundary ready.");
    } catch {
      setCryptoError(true);
      setStatus("Crypto boundary unavailable in this browser.");
    }
  };

  onCleanup(() => {
    window.removeEventListener("message", onPayloadMessage);
    defaultRuntime.lock();
  });

  /** Recovery fallback: recovery code -> local unwrap -> verify -> unlock. */
  const handleRecoveryUnlock = async (e: Event) => {
    e.preventDefault();
    if (recoveryBusy()) return;
    const activeDescriptor = descriptor();
    const identityValue = identity();
    if (!activeDescriptor || !identityValue?.configured || !identityValue.fingerprintB64) {
      setRecoveryMessage("The workspace release is not ready yet.");
      return;
    }
    // Read the recovery code, then clear both the reactive signal and the DOM
    // input before the first await. JavaScript strings cannot be zeroized, so
    // this is best-effort; only zeroizable bytes cross the async boundary.
    let raw = recoveryCodeInput();
    setRecoveryCodeInput("");
    if (recoveryInput) recoveryInput.value = "";
    let codeBytes: Uint8Array;
    try {
      codeBytes = decodeRecoveryCode(raw);
    } catch {
      setRecoveryInvalid(true);
      setRecoveryMessage("That recovery code is not valid.");
      return;
    } finally {
      raw = "";
    }
    setRecoveryBusy(true);
    setRecoveryInvalid(false);
    setRecoveryMessage("Checking your recovery code...");
    setUnlockFailure(null);
    try {
      const offline = wrappers().find(
        (wrapper) =>
          wrapper.revoked_at_ms === null &&
          isOfflineRecoveryCredential(wrapper.credential_id_b64),
      );
      if (!offline) {
        setRecoveryMessage("No offline recovery credential is registered for this workspace.");
        return;
      }
      let root: Uint8Array;
      try {
        root = await unwrapWorkspaceRootWithRecovery(offline, codeBytes);
      } catch {
        setRecoveryInvalid(true);
        setRecoveryMessage("That recovery code does not match this workspace.");
        return;
      } finally {
        codeBytes.fill(0);
      }
      if (!(await workspaceRootMatchesFingerprint(root, identityValue.fingerprintB64))) {
        root.fill(0);
        setRecoveryInvalid(true);
        setRecoveryMessage("That recovery code does not match this workspace.");
        return;
      }
      setRecoveryMessage("Unlocking...");
      await finishUnlock(root, activeDescriptor);
      setRecoveryMessage("");
      setTroubleOpen(false);
      setSecurityMessage(
        "Recovered with the offline code. Add this device's passkey from the security panel for faster unlock.",
      );
    } catch (error) {
      const failure = isUnlockError(error)
        ? recoveryFor(error.stage, error.reason)
        : recoveryFor("U7_BOOT", "unknown");
      setUnlockFailure(failure);
      defaultRuntime.lock();
      setStatus("Workspace unlock failed.");
      queueMicrotask(() => alertRef?.focus());
    } finally {
      setRecoveryBusy(false);
    }
  };

  /**
   * Post-unlock: add the current device's passkey as a stable-root wrapper. It
   * requires the offline recovery code as a trusted factor and never rotates
   * the workspace root.
   */
  const addThisPasskey = async (e: Event) => {
    e.preventDefault();
    if (recoveryBusy()) return;
    const identityValue = identity();
    if (!identityValue?.configured || !identityValue.fingerprintB64) {
      setSecurityMessage("This workspace has no stable identity yet.");
      return;
    }
    let raw = addRecoveryCode();
    setAddRecoveryCode("");
    let codeBytes: Uint8Array;
    try {
      codeBytes = decodeRecoveryCode(raw);
    } catch {
      setAddRecoveryInvalid(true);
      setSecurityMessage("Enter the recovery code to authorize adding this passkey.");
      return;
    } finally {
      raw = "";
    }
    setRecoveryBusy(true);
    setAddRecoveryInvalid(false);
    try {
      const offline = wrappers().find(
        (wrapper) =>
          wrapper.revoked_at_ms === null &&
          isOfflineRecoveryCredential(wrapper.credential_id_b64),
      );
      if (!offline) {
        setSecurityMessage("No offline recovery credential is registered.");
        return;
      }
      let root: Uint8Array;
      try {
        root = await unwrapWorkspaceRootWithRecovery(offline, codeBytes);
      } catch {
        setAddRecoveryInvalid(true);
        setSecurityMessage("That recovery code does not match this workspace.");
        return;
      } finally {
        codeBytes.fill(0);
      }
      if (!(await workspaceRootMatchesFingerprint(root, identityValue.fingerprintB64))) {
        root.fill(0);
        setAddRecoveryInvalid(true);
        setSecurityMessage("That recovery code does not match this workspace.");
        return;
      }
      setSecurityMessage("Waiting for your passkey...");
      const salt = generateRecoverySalt();
      const assertion = await authenticateWithPrf({ prfSalt: salt });
      const prfOutput = assertion.prfOutput;
      if (!prfOutput) {
        root.fill(0);
        setSecurityMessage(
          "This authenticator does not support passkey unlock (WebAuthn PRF). The recovery code remains the fallback.",
        );
        return;
      }
      const record = await wrapRootKey(
        prfOutput,
        root,
        salt,
        undefined,
        assertion.credentialIdB64,
        WORKSPACE_ROOT_KEY_SOURCE,
      );
      prfOutput.fill(0);
      root.fill(0);
      const proof = await beginRecoveryProof((sealed) =>
        defaultRuntime.decryptRecoveryChallenge(sealed),
      );
      await addRecoveryWrapper({
        challengeId: proof.challengeId,
        proofB64: proof.proofB64,
        credentialIdB64: assertion.credentialIdB64,
        label: deviceLabel().trim() || "Recovery passkey",
        record,
      });
      setSecurityMessage("This device's passkey was added.");
      await loadWrappers();
    } catch (error) {
      setSecurityMessage(
        error instanceof RecoveryClientError && error.code === "recovery_conflict"
          ? "The workspace already has the maximum number of recovery credentials."
          : "Could not add this passkey.",
      );
    } finally {
      setRecoveryBusy(false);
    }
  };

  const revokeWrapper = async (credentialIdB64: string) => {
    if (recoveryBusy()) return;
    setRecoveryBusy(true);
    try {
      const proof = await beginRecoveryProof((sealed) =>
        defaultRuntime.decryptRecoveryChallenge(sealed),
      );
      await revokeRecoveryWrapper({
        challengeId: proof.challengeId,
        proofB64: proof.proofB64,
        credentialIdB64,
      });
      setSecurityMessage(
        isOfflineRecoveryCredential(credentialIdB64)
          ? "Offline recovery code revoked. If every passkey is also lost, this workspace is unrecoverable."
          : "Recovery credential revoked.",
      );
      await loadWrappers();
    } catch {
      setSecurityMessage("Could not revoke that recovery credential.");
    } finally {
      setRecoveryBusy(false);
    }
  };

  const handleLock = () => {
    defaultRuntime.lock();
    setPayloadUrl("");
    setIsUnlocked(false);
    setUnlockFailure(null);
    setStatus("Workspace locked.");
    queueMicrotask(() => document.getElementById("open-heading")?.focus());
  };

  const needsSetup = () =>
    authState() === "authenticated" && identity()?.configured === false;
  const showSetupRecovery = () => setupPhase() === "show_recovery";

  return (
    <main class="gateway">
      <header class="gateway__masthead">
        <p class="gateway__wordmark">Evergreen</p>
        <h1 class="gateway__title">Private Workspace Gateway</h1>
        <p class="gateway__lede">
          Cloudflare Access proves the network perimeter, your passkey proves the
          operator, and the sealed release is decrypted locally in this browser.
        </p>
      </header>

      <ol class="ledger" aria-label="Security verification steps">
        <li class="ledger__item ledger__item--done">
          <span class="ledger__marker" aria-hidden="true">1</span>
          <span class="ledger__body">
            <span class="ledger__label">Perimeter</span>
            <span class="ledger__value">Cloudflare Access</span>
          </span>
        </li>
        <li
          class="ledger__item"
          classList={{
            "ledger__item--done": authState() === "authenticated",
            "ledger__item--active":
              authState() === "checking" || authState() === "authenticating",
          }}
        >
          <span class="ledger__marker" aria-hidden="true">2</span>
          <span class="ledger__body">
            <span class="ledger__label">Passkey</span>
            <span class="ledger__value">
              {authState() === "authenticated" ? "Verified" : "Pending"}
            </span>
          </span>
        </li>
        <li
          class="ledger__item"
          classList={{
            "ledger__item--done": isUnlocked(),
            "ledger__item--active": isUnlocking(),
          }}
        >
          <span class="ledger__marker" aria-hidden="true">3</span>
          <span class="ledger__body">
            <span class="ledger__label">Workspace</span>
            <span class="ledger__value">
              {isUnlocked() ? "Unlocked locally" : "Locked"}
            </span>
          </span>
        </li>
      </ol>

      <p id="status" class="gateway__status" role="status" aria-live="polite">
        {status()}
      </p>

      <Show when={unlockFailure()}>
        {(failure) => (
          <div
            id="unlock-failure"
            class="notice"
            classList={{
              "notice--error": failure().severity === "error",
              "notice--warning": failure().severity === "warning",
            }}
            role="alert"
            tabindex={-1}
            ref={(element) => {
              alertRef = element;
            }}
          >
            <p class="notice__stage">{failure().stageLabel}</p>
            <p class="notice__title">{failure().title}</p>
            <p class="notice__detail">{failure().detail}</p>
            <Show when={RECOVERY_ACTION_LABELS[failure().action]}>
              {(label) => (
                <button
                  type="button"
                  class="button"
                  onClick={() => runRecoveryAction(failure().action)}
                >
                  {label()}
                </button>
              )}
            </Show>
          </div>
        )}
      </Show>

      <Show when={descriptorError()}>
        <div class="notice notice--error" role="alert">
          <p class="notice__title">Release unavailable</p>
          <p class="notice__detail">{descriptorError()}</p>
          <button
            type="button"
            class="button"
            onClick={refreshAccess}
            disabled={descriptorLoading() || authState() !== "authenticated"}
          >
            {descriptorLoading() ? "Checking release..." : "Retry release check"}
          </button>
        </div>
      </Show>

      <Show when={identityError()}>
        <div class="notice notice--error" role="alert">
          <p class="notice__title">Workspace identity unavailable</p>
          <p class="notice__detail">{identityError()}</p>
          <button
            type="button"
            class="button"
            onClick={refreshAccess}
            disabled={authState() !== "authenticated"}
          >
            Retry
          </button>
        </div>
      </Show>

      <Show when={cryptoError()}>
        <div class="notice notice--error" role="alert">
          <p class="notice__title">The browser crypto module did not load.</p>
          <p class="notice__detail">
            This browser cannot unlock the workspace. Retry the module, reload the
            page, or use a current browser that supports WebAssembly cryptography.
          </p>
          <button type="button" class="button" onClick={retryCrypto}>
            Retry crypto module
          </button>
        </div>
      </Show>

      {/* Normal login: Cloudflare Access -> Passkey -> Workspace. No KID, key,
          fingerprint, release-compatibility or recovery-code input is shown. */}
      <Show when={!isUnlocked()}>
        <section class="panel" aria-labelledby="open-heading">
          <h2 id="open-heading" class="panel__heading" tabindex={-1}>
            Open the private workspace
          </h2>
          <p id="auth-message" class="panel__copy" role="status" aria-live="polite">
            {authMessage()}
          </p>
          <div class="actions">
            <Show
              when={authState() === "authenticated"}
              fallback={
                <button
                  type="button"
                  class="button button--primary"
                  onClick={runAuthentication}
                  disabled={
                    authState() === "authenticating" ||
                    authState() === "unsupported" ||
                    authState() === "checking"
                  }
                >
                  {authState() === "authenticating"
                    ? "Verifying passkey..."
                    : "Open Private Workspace"}
                </button>
              }
            >
              <p id="auth-status" class="panel__verified" role="status">
                {needsSetup() ? "Workspace setup required." : "Passkey verified."}
              </p>
            </Show>
          </div>

          <Show when={enrollmentOpen()}>
            <details class="advanced">
              <summary>First-run operator enrollment</summary>
              <form class="form" onSubmit={handleEnroll}>
                <label class="field" for="enroll-secret">
                  <span class="field__label">Operator enrollment secret</span>
                  <input
                    id="enroll-secret"
                    class="field__input"
                    type="password"
                    autocomplete="off"
                    spellcheck={false}
                    value={enrollSecret()}
                    onInput={(e) => setEnrollSecret(e.currentTarget.value)}
                    disabled={isEnrolling()}
                    aria-invalid={enrollInvalid() ? "true" : "false"}
                    aria-describedby={enrollInvalid() ? "auth-message" : undefined}
                  />
                </label>
                <button class="button" type="submit" disabled={isEnrolling()}>
                  {isEnrolling() ? "Enrolling..." : "Enroll passkey"}
                </button>
              </form>
            </details>
          </Show>
        </section>

        {/* Initial setup: generate the stable root + recovery code locally.
            This intentionally does not require a published release: the stable
            identity must be creatable on a clean deployment, and the release is
            then sealed to it. */}
        <Show when={needsSetup()}>
          <section class="panel" aria-labelledby="setup-heading">
            <h2 id="setup-heading" class="panel__heading">
              Set up this workspace
            </h2>
            <p class="panel__copy">
              This workspace has no root key yet. This browser will generate a
              stable workspace root and a one-time recovery code locally; only
              the public identity and encrypted wrappers are uploaded.
            </p>
            <Show when={setupError()}>
              <p class="notice notice--error" role="alert">
                <span class="notice__detail">{setupError()}</span>
              </p>
            </Show>
            <button
              type="button"
              class="button button--primary"
              onClick={runInitialSetup}
              disabled={setupPhase() === "preparing" || !cryptoReady()}
            >
              {setupPhase() === "preparing"
                ? "Creating workspace..."
                : "Create this workspace"}
            </button>
          </section>
        </Show>

        {/* Unlocking progress and the trouble/recovery entry point. */}
        <Show
          when={
            authState() === "authenticated" &&
            identity()?.configured === true &&
            !needsSetup()
          }
        >
          <section class="panel" aria-labelledby="unlock-heading">
            <h2 id="unlock-heading" class="panel__heading">
              Unlock the sealed release
            </h2>
            <p class="panel__copy">
              Your passkey unwraps this workspace's root key locally. The sealed
              release is decrypted in memory and never leaves this browser.
            </p>

            <Show when={isUnlocking() || unlockStage()}>
              <div role="status" aria-live="polite">
                <ol class="stages" aria-label="Unlock progress">
                  <For each={STAGES}>
                    {(stage) => (
                      <li
                        class="stages__item"
                        classList={{
                          "stages__item--done":
                            unlockStage() !== null &&
                            STAGES.findIndex((s) => s.id === stage.id) <
                              STAGES.findIndex((s) => s.id === unlockStage()),
                          "stages__item--active": unlockStage() === stage.id,
                          "stages__item--pending":
                            unlockStage() !== null &&
                            STAGES.findIndex((s) => s.id === stage.id) >
                              STAGES.findIndex((s) => s.id === unlockStage()),
                        }}
                      >
                        <span class="stages__dot" aria-hidden="true" />
                        <span class="stages__label">{stage.label}</span>
                        <span class="stages__state">
                          {stageStatusText(unlockStage(), stage.id)}
                        </span>
                      </li>
                    )}
                  </For>
                </ol>
              </div>
            </Show>

            <Show when={!troubleOpen() && !isUnlocking()}>
              <button
                type="button"
                class="button"
                onClick={() => {
                  setTroubleOpen(true);
                  queueMicrotask(() => recoveryInput?.focus());
                }}
              >
                Having trouble signing in?
              </button>
            </Show>

            <Show when={troubleOpen()}>
              <form class="form" onSubmit={handleRecoveryUnlock}>
                <label class="field" for="recovery-code">
                  <span class="field__label">Offline recovery code</span>
                  <input
                    id="recovery-code"
                    class="field__input field__input--code"
                    type="password"
                    autocomplete="off"
                    autocapitalize="off"
                    autocorrect="off"
                    spellcheck={false}
                    placeholder="Recovery code"
                    value={recoveryCodeInput()}
                    onInput={(e) => setRecoveryCodeInput(e.currentTarget.value)}
                    disabled={recoveryBusy()}
                    aria-invalid={recoveryInvalid() ? "true" : "false"}
                    aria-describedby={recoveryMessage() ? "recovery-message" : undefined}
                    ref={(element) => {
                      recoveryInput = element;
                    }}
                  />
                </label>
                <button
                  class="button button--primary"
                  type="submit"
                  disabled={recoveryBusy() || !cryptoReady()}
                >
                  {recoveryBusy() ? "Checking..." : "Unlock with recovery code"}
                </button>
              </form>
              <Show when={recoveryMessage()}>
                <p id="recovery-message" class="panel__note" role="status" aria-live="polite">
                  {recoveryMessage()}
                </p>
              </Show>
            </Show>
          </section>
        </Show>
      </Show>

      {/* Recovery code is shown exactly once, gated on explicit confirmation. */}
      <Show when={showSetupRecovery()}>
        <section class="panel" aria-labelledby="recovery-code-heading">
          <h2 id="recovery-code-heading" class="panel__heading">
            Save your offline recovery code
          </h2>
          <p class="panel__copy">
            This code is shown once. It is the only way to recover this workspace
            if you lose every passkey. It is never sent to the server.
          </p>
          <p class="fingerprint__value fingerprint__value--mono" data-testid="recovery-code">
            {setupRecoveryCode()}
          </p>
          <label class="field">
            <input
              type="checkbox"
              checked={savedConfirmed()}
              onChange={(event) => setSavedConfirmed(event.currentTarget.checked)}
            />
            <span class="field__label">
              I have saved this recovery code somewhere safe.
            </span>
          </label>
          <button
            type="button"
            class="button button--primary"
            onClick={confirmRecoverySaved}
            disabled={!savedConfirmed()}
          >
            Continue to workspace
          </button>
        </section>
      </Show>

      <Show when={isUnlocked() && !showSetupRecovery()}>
        <section class="workspace" id="workspace-region" tabindex={-1} aria-label="Private workspace">
          <div class="workspace__bar">
            <p class="workspace__state" role="status">
              Workspace open — decrypted in memory only.
            </p>
            <button type="button" class="button" onClick={handleLock}>
              Lock Workspace
            </button>
          </div>
          <iframe
            id="workspace-frame"
            ref={(element) => {
              frame = element;
            }}
            src={payloadUrl()}
            onLoad={(event) => defaultRuntime.releaseDocumentUrl(event.currentTarget.src)}
            title="Private trading workspace"
            sandbox="allow-scripts allow-same-origin"
            class="workspace-frame"
          />
        </section>

        <section class="panel" aria-labelledby="security-heading">
          <h2 id="security-heading" class="panel__heading">
            Workspace security
          </h2>
          <p class="panel__copy">
            Each credential wraps this workspace's stable root key locally. Revoking
            a credential never rotates the root; the offline recovery code remains
            the fallback.
          </p>
          <Show when={wrappers().length > 0}>
            <ul class="devices">
              <For each={wrappers()}>
                {(wrapper) => (
                  <li class="devices__row">
                    <span class="devices__label">
                      {isOfflineRecoveryCredential(wrapper.credential_id_b64)
                        ? "Offline recovery code"
                        : wrapper.label}
                    </span>
                    <span class="devices__meta">
                      {wrapper.revoked_at_ms !== null
                        ? "Revoked"
                        : wrapper.last_used_at_ms !== null
                          ? "Used recently"
                          : "Not yet used"}
                    </span>
                    <Show when={wrapper.revoked_at_ms === null}>
                      <button
                        type="button"
                        class="button"
                        disabled={recoveryBusy()}
                        onClick={() => revokeWrapper(wrapper.credential_id_b64)}
                      >
                        Revoke
                      </button>
                    </Show>
                  </li>
                )}
              </For>
            </ul>
          </Show>
          <Show when={wrappers().length === 0}>
            <p class="panel__note">No recovery credentials are registered yet.</p>
          </Show>
          <details class="advanced">
            <summary>Add this device's passkey</summary>
            <form class="form" onSubmit={addThisPasskey}>
              <label class="field" for="device-label">
                <span class="field__label">Device label</span>
                <input
                  id="device-label"
                  class="field__input"
                  value={deviceLabel()}
                  onInput={(event) => setDeviceLabel(event.currentTarget.value)}
                  disabled={recoveryBusy()}
                />
              </label>
              <label class="field" for="add-recovery-code">
                <span class="field__label">
                  Offline recovery code (authorizes adding this passkey)
                </span>
                <input
                  id="add-recovery-code"
                  class="field__input field__input--code"
                  type="password"
                  autocomplete="off"
                  autocapitalize="off"
                  autocorrect="off"
                  spellcheck={false}
                  value={addRecoveryCode()}
                  onInput={(event) => setAddRecoveryCode(event.currentTarget.value)}
                  disabled={recoveryBusy()}
                  aria-invalid={addRecoveryInvalid() ? "true" : "false"}
                  aria-describedby={addRecoveryInvalid() ? "security-message" : undefined}
                />
              </label>
              <button class="button" type="submit" disabled={recoveryBusy()}>
                {recoveryBusy() ? "Working..." : "Add this passkey"}
              </button>
            </form>
          </details>
          <Show when={securityMessage()}>
            <p id="security-message" class="panel__note" role="status" aria-live="polite">
              {securityMessage()}
            </p>
          </Show>
        </section>
      </Show>

      <footer class="gateway__footer">
        <p>
          The perimeter and your passkey prove identity. The release is decrypted
          locally from this workspace's stable root key; no key material leaves
          this browser.
        </p>
      </footer>
    </main>
  );
}

render(() => <App />, document.getElementById("root")!);
