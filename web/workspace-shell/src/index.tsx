import { render } from "solid-js/web";
import { createSignal, onMount, onCleanup, Show, For } from "solid-js";
import "./style.css";
import { loadWasm, defaultRuntime, fromBase64 } from "./unlock-runtime";
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
  fetchRecoveryWrappers,
  fromBase64 as recoveryFromBase64,
  revokeRecoveryWrapper,
  touchRecoveryWrapper,
  unwrapWithPrfOutput,
  type RecoveryWrapperRecord,
} from "./recovery-client";
import {
  generateRecoverySalt,
  wrapRootKey,
} from "./recovery-wrapping";
import { authenticateWithPrf } from "./recovery-passkey";
import {
  isUnlockError,
  recoveryFor,
  type UnlockRecovery,
  type UnlockStage,
} from "./unlock-stages";

type AuthState =
  | "checking"
  | "signed_out"
  | "authenticating"
  | "authenticated"
  | "unsupported";

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

function shortDigest(hex: string): string {
  if (!hex) return "unavailable";
  return hex.slice(0, 12).replace(/(.{4})(?=.)/g, "$1 ");
}

function App() {
  const [status, setStatus] = createSignal("Security gateway ready.");
  const [authState, setAuthState] = createSignal<AuthState>("checking");
  const [authMessage, setAuthMessage] = createSignal(
    "Checking whether an operator session already exists...",
  );
  const [enrollmentOpen, setEnrollmentOpen] = createSignal(false);
  const [descriptor, setDescriptor] = createSignal<WorkspaceDescriptor | null>(null);
  const [descriptorError, setDescriptorError] = createSignal("");
  const [descriptorLoading, setDescriptorLoading] = createSignal(false);
  const [recoveryCode, setRecoveryCode] = createSignal("");
  const [unlockStage, setUnlockStage] = createSignal<UnlockStage | null>(null);
  const [unlockFailure, setUnlockFailure] = createSignal<UnlockRecovery | null>(null);
  const [isUnlocking, setIsUnlocking] = createSignal(false);
  const [cryptoReady, setCryptoReady] = createSignal(false);
  const [isUnlocked, setIsUnlocked] = createSignal(false);
  const [payloadUrl, setPayloadUrl] = createSignal("");
  const [enrollSecret, setEnrollSecret] = createSignal("");
  const [isEnrolling, setIsEnrolling] = createSignal(false);
  const [recoveryWrappers, setRecoveryWrappers] = createSignal<
    RecoveryWrapperRecord[]
  >([]);
  const [recoveryAvailable, setRecoveryAvailable] = createSignal(false);
  const [recoveryBusy, setRecoveryBusy] = createSignal(false);
  const [recoveryMessage, setRecoveryMessage] = createSignal("");
  const [deviceLabel, setDeviceLabel] = createSignal("This device");
  const [addRecoveryCode, setAddRecoveryCode] = createSignal("");
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

  const loadDescriptor = async () => {
    setDescriptorError("");
    setDescriptor(null);
    setDescriptorLoading(true);
    try {
      const value = await fetchWorkspaceDescriptor();
      setDescriptor(value);
    } catch (error) {
      if (error instanceof DescriptorError && error.code === "descriptor_unauthorized") {
        setAuthState("signed_out");
        setAuthMessage("Operator session required. Open the private workspace to verify your passkey.");
        return;
      }
      setDescriptorError(
        "The server did not publish a usable workspace release descriptor. Retry, or contact the operator.",
      );
    } finally {
      setDescriptorLoading(false);
    }
  };

  const loadRecoveryWrappers = async () => {
    try {
      const wrappers = await fetchRecoveryWrappers();
      setRecoveryWrappers(wrappers);
      setRecoveryAvailable(true);
    } catch {
      // Passkey recovery is optional; a closed surface or transient failure
      // leaves the mandatory offline recovery code as the only credential.
      setRecoveryWrappers([]);
      setRecoveryAvailable(false);
    }
  };

  const runAuthentication = async () => {
    setAuthState("authenticating");
    setAuthMessage("Waiting for your passkey...");
    setUnlockFailure(null);
    try {
      await authenticateWithPasskey();
      setAuthState("authenticated");
      setAuthMessage("Operator identity verified.");
      await loadDescriptor();
      void loadRecoveryWrappers();
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
        await loadDescriptor();
        void loadRecoveryWrappers();
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
    const secretValue = enrollSecret().trim();
    setEnrollSecret("");
    if (!secretValue) {
      setAuthMessage("Enrollment secret required.");
      return;
    }
    setIsEnrolling(true);
    setAuthMessage("Enrolling passkey...");
    try {
      await enrollPasskey(secretValue);
      await runAuthentication();
    } catch (error) {
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
      setStatus("Crypto boundary ready.");
    } catch {
      setStatus("Crypto boundary unavailable in this browser.");
    }
    await loadEnrollmentStatus();
    await checkExistingSession();
  });

  onCleanup(() => {
    window.removeEventListener("message", onPayloadMessage);
    defaultRuntime.lock();
  });

  const handleUnlock = async (e: Event) => {
    e.preventDefault();
    if (isUnlocking()) return;
    const activeDescriptor = descriptor();
    if (!activeDescriptor) {
      setDescriptorError("The release descriptor is not available yet.");
      return;
    }

    // Read the recovery code, then clear the reactive signal *and* the DOM
    // input before the first network await. JavaScript strings cannot be
    // zeroized, so this is best-effort: the reference is dropped right after
    // decoding and only zeroizable bytes cross the async boundary below.
    let raw = recoveryCode();
    setRecoveryCode("");
    if (recoveryInput) recoveryInput.value = "";

    let secretBytes: Uint8Array;
    try {
      secretBytes = fromBase64(raw.trim());
    } catch {
      setUnlockFailure(recoveryFor("U2_ENROLL", "invalid_secret"));
      return;
    } finally {
      raw = "";
    }
    if (secretBytes.length !== 32 || secretBytes.every((b) => b === 0)) {
      secretBytes.fill(0);
      setUnlockFailure(recoveryFor("U2_ENROLL", "invalid_secret"));
      return;
    }

    setIsUnlocking(true);
    setUnlockFailure(null);
    setUnlockStage("U1_WASM");
    setStatus("Decrypting the private workspace in memory...");

    // The runtime copies the secret synchronously before its first await, so the
    // caller's plaintext buffer is dropped immediately instead of surviving the
    // whole network exchange.
    const unlockPromise = defaultRuntime.unlock(secretBytes, activeDescriptor, {
      onStage: (stage) => setUnlockStage(stage),
    });
    secretBytes.fill(0);

    try {
      const result = await unlockPromise;
      setPayloadUrl(result.htmlUrl);
      setIsUnlocked(true);
      setStatus("Private workspace opened.");
    } catch (error) {
      const failure = isUnlockError(error)
        ? recoveryFor(error.stage, error.reason)
        : recoveryFor("U7_BOOT", "unknown");
      setUnlockFailure(failure);
      setStatus("Workspace unlock failed.");
      if (
        isUnlockError(error) &&
        error.stage === "U2_ENROLL" &&
        error.reason === "enrollment_required"
      ) {
        // The cached descriptor claimed an enrollment the server no longer has
        // for this session; refetch so a retry posts the enrollment again
        // instead of deterministically skipping it.
        void loadDescriptor();
      }
      defaultRuntime.lock();
      queueMicrotask(() => alertRef?.focus());
    } finally {
      setUnlockStage(null);
      setIsUnlocking(false);
    }
  };

  /**
   * New-device path: unwrap the workspace secret through a registered passkey
   * (WebAuthn PRF) instead of typing the offline recovery code. Falls back to
   * the code when the authenticator returns no PRF output.
   */
  const unlockWithRecoveryPasskey = async () => {
    if (isUnlocking()) return;
    const activeDescriptor = descriptor();
    if (!activeDescriptor) {
      setDescriptorError("The release descriptor is not available yet.");
      return;
    }
    const wrappers = recoveryWrappers().filter(
      (wrapper) => wrapper.revoked_at_ms === null,
    );
    if (wrappers.length === 0) {
      setRecoveryMessage("No recovery passkey is registered for this workspace.");
      return;
    }
    setIsUnlocking(true);
    setUnlockFailure(null);
    setRecoveryMessage("Waiting for your recovery passkey...");
    setUnlockStage("U1_WASM");
    try {
      for (const wrapper of wrappers) {
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
        let secret: Uint8Array | null = null;
        try {
          secret = await unwrapWithPrfOutput(prfOutput, wrapper);
        } catch {
          continue;
        } finally {
          prfOutput.fill(0);
        }
        if (!secret) continue;
        try {
          const result = await defaultRuntime.unlock(secret, activeDescriptor, {
            onStage: (stage) => setUnlockStage(stage),
          });
          setPayloadUrl(result.htmlUrl);
          setIsUnlocked(true);
          setStatus("Private workspace opened.");
          setRecoveryMessage("");
          void touchRecoveryWrapper(credentialIdB64);
          return;
        } catch (error) {
          const failure = isUnlockError(error)
            ? recoveryFor(error.stage, error.reason)
            : recoveryFor("U7_BOOT", "unknown");
          setUnlockFailure(failure);
          setStatus("Workspace unlock failed.");
          defaultRuntime.lock();
          queueMicrotask(() => alertRef?.focus());
          return;
        } finally {
          secret.fill(0);
        }
      }
      setRecoveryMessage(
        "No recovery passkey on this device. Enter your offline recovery code.",
      );
    } finally {
      setUnlockStage(null);
      setIsUnlocking(false);
    }
  };

  /**
   * Add the current passkey as a recovery credential. Adding requires an
   * existing trusted recovery factor, so the offline recovery code is
   * re-entered once to authorize the wrap; the code never leaves the browser.
   */
  const addRecoveryPasskey = async (e: Event) => {
    e.preventDefault();
    if (recoveryBusy()) return;
    let raw = addRecoveryCode();
    setAddRecoveryCode("");
    let secret: Uint8Array;
    try {
      secret = fromBase64(raw.trim());
    } catch {
      secret = new Uint8Array(0);
    } finally {
      raw = "";
    }
    if (secret.length !== 32 || secret.every((byte) => byte === 0)) {
      secret.fill(0);
      setRecoveryMessage(
        "Enter the 32-byte offline recovery code to authorize adding this passkey.",
      );
      return;
    }
    setRecoveryBusy(true);
    setRecoveryMessage("Waiting for your passkey...");
    let prfOutput: Uint8Array | null = null;
    try {
      const salt = generateRecoverySalt();
      const assertion = await authenticateWithPrf({ prfSalt: salt });
      prfOutput = assertion.prfOutput;
      if (!prfOutput) {
        setRecoveryMessage(
          "This authenticator or browser does not support passkey recovery (WebAuthn PRF). Your offline recovery code remains the fallback.",
        );
        return;
      }
      const wrapped = await wrapRootKey(prfOutput, secret, salt);
      const proof = await beginRecoveryProof((sealed) =>
        defaultRuntime.decryptRecoveryChallenge(sealed),
      );
      await addRecoveryWrapper({
        challengeId: proof.challengeId,
        proofB64: proof.proofB64,
        credentialIdB64: assertion.credentialIdB64,
        label: deviceLabel().trim() || "Recovery passkey",
        record: wrapped,
      });
      setRecoveryMessage("Recovery passkey added for this workspace.");
      await loadRecoveryWrappers();
    } catch (error) {
      setRecoveryMessage(
        error instanceof RecoveryClientError && error.code === "recovery_conflict"
          ? "The workspace already has the maximum number of recovery credentials."
          : "Could not add the recovery passkey.",
      );
    } finally {
      if (prfOutput) prfOutput.fill(0);
      secret.fill(0);
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
      setRecoveryMessage("Recovery credential revoked.");
      await loadRecoveryWrappers();
    } catch {
      setRecoveryMessage("Could not revoke that recovery credential.");
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
  };

  return (
    <main class="gateway">
      <header class="gateway__masthead">
        <p class="gateway__wordmark">Evergreen</p>
        <h1 class="gateway__title">Private Workspace Gateway</h1>
        <p class="gateway__lede">
          Three independent checks stand between this browser and the private
          trading workspace: the network perimeter, your passkey, and the local
          decryption of the sealed release.
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
            <span class="ledger__label">Operator</span>
            <span class="ledger__value">
              {authState() === "authenticated" ? "Passkey verified" : "Passkey pending"}
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
              {isUnlocked() ? "Decrypted locally" : "Sealed"}
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
          </div>
        )}
      </Show>

      <Show when={descriptorError()}>
        <div class="notice notice--error" role="alert">
          <p class="notice__title">Release descriptor unavailable</p>
          <p class="notice__detail">{descriptorError()}</p>
          <button
            type="button"
            class="button"
            onClick={loadDescriptor}
            disabled={descriptorLoading() || authState() !== "authenticated"}
          >
            {descriptorLoading() ? "Checking release..." : "Retry release check"}
          </button>
        </div>
      </Show>

      <Show when={!isUnlocked()}>
        <section class="panel" aria-labelledby="open-heading">
          <h2 id="open-heading" class="panel__heading">
            Open the private workspace
          </h2>
          <p class="panel__copy">
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
                Operator session established. Release metadata loaded automatically.
              </p>
            </Show>
          </div>

          <Show when={enrollmentOpen()}>
            <details class="advanced">
              <summary>First-run passkey enrollment</summary>
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
                  />
                </label>
                <button class="button" type="submit" disabled={isEnrolling()}>
                  {isEnrolling() ? "Enrolling..." : "Enroll passkey"}
                </button>
              </form>
            </details>
          </Show>
        </section>

        <Show when={authState() === "authenticated" && descriptor()}>
          {(active) => (
            <section class="panel" aria-labelledby="unlock-heading">
              <h2 id="unlock-heading" class="panel__heading">
                Unlock the sealed release
              </h2>
              <p class="panel__copy">
                Enter your high-entropy offline recovery code. It is decoded to
                bytes locally, cleared from this form before any network call,
                and never sent to the server.
              </p>
              <p class="panel__note">
                Passkey-bound recovery is offered only once this workspace
                publishes a wrapped root key and your authenticator verifies
                WebAuthn PRF support. Until then the offline recovery code is
                the only unlock credential.
              </p>

              <div class="fingerprint" aria-label="Active release">
                <div class="fingerprint__row">
                  <span class="fingerprint__key">Release</span>
                  <span class="fingerprint__value">
                    {active().release_id ?? "unversioned"}
                  </span>
                </div>
                <div class="fingerprint__row">
                  <span class="fingerprint__key">Artifact digest</span>
                  <span class="fingerprint__value fingerprint__value--mono">
                    {shortDigest(active().artifact_sha256_hex)}
                  </span>
                </div>
                <div class="fingerprint__row">
                  <span class="fingerprint__key">Key binding</span>
                  <span class="fingerprint__value">
                    {active().expected_public_key_fingerprint_b64
                      ? "Pinned to this release"
                      : "Not pinned (legacy)"}
                  </span>
                </div>
                <details class="advanced">
                  <summary>Protocol metadata</summary>
                  <dl class="meta">
                    <div class="meta__row">
                      <dt>Artifact version</dt>
                      <dd>{active().artifact_version}</dd>
                    </div>
                    <div class="meta__row">
                      <dt>Package format</dt>
                      <dd>{active().package_format_version}</dd>
                    </div>
                    <div class="meta__row">
                      <dt>Workspace protocol</dt>
                      <dd>
                        {active().min_shell_protocol}–{active().max_shell_protocol}
                      </dd>
                    </div>
                  </dl>
                </details>
              </div>

              <form class="form" onSubmit={handleUnlock}>
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
                    placeholder="32-byte base64 recovery code"
                    value={recoveryCode()}
                    onInput={(e) => setRecoveryCode(e.currentTarget.value)}
                    disabled={isUnlocking()}
                    ref={(element) => {
                      recoveryInput = element;
                    }}
                  />
                </label>
                <button
                  class="button button--primary"
                  type="submit"
                  disabled={isUnlocking() || !cryptoReady()}
                >
                  {!cryptoReady()
                    ? "Preparing crypto..."
                    : isUnlocking()
                      ? "Unlocking..."
                      : "Unlock Workspace"}
                </button>
              </form>

              <Show
                when={recoveryWrappers().some(
                  (wrapper) => wrapper.revoked_at_ms === null,
                )}
              >
                <div class="recovery-passkey">
                  <p class="panel__copy">
                    A recovery passkey is registered for this workspace. Verify it
                    to unwrap the release without typing the offline code.
                  </p>
                  <button
                    type="button"
                    class="button"
                    onClick={unlockWithRecoveryPasskey}
                    disabled={isUnlocking() || !cryptoReady()}
                  >
                    Unlock with a recovery passkey
                  </button>
                </div>
              </Show>

              <Show when={recoveryMessage()}>
                <p class="panel__note" role="status">
                  {recoveryMessage()}
                </p>
              </Show>

              <Show when={isUnlocking() || unlockStage()}>
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
                          {unlockStage() === stage.id ? "in progress" : ""}
                        </span>
                      </li>
                    )}
                  </For>
                </ol>
              </Show>
            </section>
          )}
        </Show>
      </Show>

      <Show when={isUnlocked()}>
        <section class="workspace" aria-label="Private workspace">
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

        <Show when={recoveryAvailable()}>
          <section class="panel" aria-labelledby="devices-heading">
            <h2 id="devices-heading" class="panel__heading">
              Trusted recovery credentials
            </h2>
            <p class="panel__copy">
              Each credential wraps this workspace's root key locally. Revoking a
              credential never rotates the key; the offline recovery code always
              remains a fallback.
            </p>
            <ul class="devices">
              <For each={recoveryWrappers()}>
                {(wrapper) => (
                  <li class="devices__row">
                    <span class="devices__label">{wrapper.label}</span>
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
            <Show when={recoveryWrappers().length === 0}>
              <p class="panel__note">No recovery passkey is registered yet.</p>
            </Show>
            <form class="form" onSubmit={addRecoveryPasskey}>
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
                />
              </label>
              <button class="button" type="submit" disabled={recoveryBusy()}>
                {recoveryBusy() ? "Working..." : "Add this passkey"}
              </button>
            </form>
            <Show when={recoveryMessage()}>
              <p class="panel__note" role="status">
                {recoveryMessage()}
              </p>
            </Show>
          </section>
        </Show>
      </Show>

      <footer class="gateway__footer">
        <p>
          The perimeter and your passkey prove identity. Only the local recovery
          code decrypts the release; it never leaves this browser.
        </p>
      </footer>
    </main>
  );
}

render(() => <App />, document.getElementById("root")!);
