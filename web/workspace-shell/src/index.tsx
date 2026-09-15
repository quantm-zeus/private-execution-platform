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
  const [recoveryCode, setRecoveryCode] = createSignal("");
  const [unlockStage, setUnlockStage] = createSignal<UnlockStage | null>(null);
  const [unlockFailure, setUnlockFailure] = createSignal<UnlockRecovery | null>(null);
  const [isUnlocking, setIsUnlocking] = createSignal(false);
  const [cryptoReady, setCryptoReady] = createSignal(false);
  const [isUnlocked, setIsUnlocked] = createSignal(false);
  const [payloadUrl, setPayloadUrl] = createSignal("");
  const [enrollSecret, setEnrollSecret] = createSignal("");
  const [isEnrolling, setIsEnrolling] = createSignal(false);
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
    const secretValue = enrollSecret();
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
      defaultRuntime.lock();
      queueMicrotask(() => alertRef?.focus());
    } finally {
      setUnlockStage(null);
      setIsUnlocking(false);
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
                      <dt>Artifact key ID</dt>
                      <dd class="meta__mono">{active().artifact_kid_b64}</dd>
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

              <Show when={isUnlocking() || unlockStage()}>
                <ol class="stages" aria-label="Unlock progress">
                  <For each={STAGES}>
                    {(stage) => (
                      <li
                        class="stages__item"
                        classList={{
                          "stages__item--active": unlockStage() === stage.id,
                          "stages__item--pending":
                            STAGES.findIndex((s) => s.id === stage.id) <
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
            onLoad={() => defaultRuntime.releaseDocumentUrl(payloadUrl())}
            title="Private trading workspace"
            sandbox="allow-scripts allow-same-origin"
            class="workspace-frame"
          />
        </section>
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
