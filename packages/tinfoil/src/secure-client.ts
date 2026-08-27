import { KeyConfigMismatchError } from "ehbp";
import {
  VERIFICATION_DOCUMENT_SCHEMA_VERSION,
  VERIFIER_NAME,
  VERIFIER_VERSION,
  VerificationError,
  PredicateType,
  measurementFingerprint,
} from "@tinfoilsh/verifier";
import {
  cloneVerificationDocument,
  ConfigurationError,
  FetchError,
  AttestationError,
  fetchAttestation,
  randomNonce,
  verifyDocumentV3,
  tlsPublicKeyFP,
  hpkePublicKey,
  type VerificationDocument,
  type VerifiedDocumentV3,
  type AttestationMeasurement,
  type HardwareMeasurement,
} from "./verifier.js";
import { TINFOIL_CONFIG } from "./config.js";
import { createSecureFetch } from "./secure-fetch.js";
import { resolveUserCacheSecret } from "./user-cache-secret.js";
import { fetchRouter } from "./atc.js";
import type { SecureTransport, SessionRecoveryToken } from "./encrypted-body-fetch.js";
import type { SecureWebSocketOptions } from "./pinned-ws.js";
import type * as WS from "ws";
import { isRealBrowser } from "./env.js";

export type { SecureWebSocketOptions } from "./pinned-ws.js";

/** Delay before retrying init on transient failure (ms). */
const INIT_RETRY_DELAY_MS = 1000;

/**
 * Transport mode for secure communication with the enclave.
 *
 * - `'ehbp'` - HPKE encryption via the Encrypted HTTP Body Protocol (default).
 *   End-to-end encrypted, works through proxies.
 * - `'tls'` - TLS certificate pinning. Requires direct connection to the enclave;
 *   requests through a proxy will fail.
 *
 * @see https://docs.tinfoil.sh/resources/ehbp - EHBP Protocol specification
 */
export type TransportMode = 'ehbp' | 'tls';

/**
 * Configuration options for SecureClient.
 */
export interface SecureClientOptions {
  /**
   * Override the base URL for API requests.
   * This may be a proxy URL when using EHBP or a custom path on the enclave
   * origin when using TLS pinning.
   * @see https://docs.tinfoil.sh/guides/proxy-server
   */
  baseURL?: string;

  /**
   * Explicit enclave URL. When set, this takes precedence over router
   * discovery.
   * Use this when connecting to a custom enclave endpoint rather than the default router.
   */
  enclaveURL?: string;

  /** GitHub repo for code verification. Defaults to tinfoilsh/confidential-model-router. */
  configRepo?: string;

  /**
   * Transport mode for secure communication.
   * @default 'ehbp'
   */
  transport?: TransportMode;

  /** Base URL of the ATC service used for router discovery. */
  attestationBundleURL?: string;

  /**
   * Secret scoping the router's prompt cache for this client's requests.
   * Under the same authenticated API identity, requests carrying the same
   * secret share cached prompt prefixes; requests carrying different
   * identities or secrets cannot observe each other's cache timing.
   *
   * Defaults to the TINFOIL_USER_CACHE_SECRET environment variable when set,
   * otherwise attempts to generate a secret persisted at
   * `~/.tinfoil/user_cache_secret` in Node.js (shared with other Tinfoil SDKs
   * using the same home directory). Browsers cannot persist it and use a
   * process-lifetime in-memory secret instead. Empty values are treated as
   * unset. A non-empty
   * `user_cache_secret` field already present in a request body wins over this
   * option.
   */
  userCacheSecret?: string;
}

// TDX predicate + zeroed RTMR3 (Go: verifier/measurement). The legacy
// PredicateType enum predates TDX support, so the URL is pinned here.
const TDX_GUEST_V2 = "https://tinfoil.sh/predicate/tdx-guest/v2";
const RTMR3_ZERO = "0".repeat(96);

/**
 * Projects a measurement onto the enclave's platform registers, then applies
 * the shared fingerprint rule (Go: measurement.Fingerprint).
 */
async function fingerprintFor(
  m: AttestationMeasurement,
  hw: HardwareMeasurement | undefined,
  targetType: string,
): Promise<string> {
  let registers: string[];
  switch (m.type) {
    case PredicateType.SnpTdxMultiplatformV1: // Source
      if (targetType === PredicateType.SevGuestV2) {
        registers = [m.registers[0]];
      } else if (targetType === TDX_GUEST_V2) {
        if (!hw) {
          throw new AttestationError("hardware measurement required for TDX guest types");
        }
        registers = [hw.MRTD!, hw.RTMR0!, m.registers[1], m.registers[2], RTMR3_ZERO];
      } else {
        throw new AttestationError(`unsupported target type ${targetType}`);
      }
      break;
    case TDX_GUEST_V2: // Runtime
      if (m.registers.length < 5) {
        throw new AttestationError(`TDX measurement has ${m.registers.length} registers, want 5`);
      }
      registers = m.registers.slice(0, 5);
      break;
    case PredicateType.SevGuestV2:
      registers = [m.registers[0]];
      break;
    default:
      throw new AttestationError(`unsupported measurement type ${m.type}`);
  }
  return measurementFingerprint({ type: m.type, registers });
}

/** Maps a v3 rejection layer to the verification-document step it fails. */
function stepForLayer(layer: VerificationError["layer"]): "verifyCode" | "verifyEnclave" | "compareMeasurements" {
  switch (layer) {
    case "PROVENANCE_REJECTED":
      return "verifyCode";
    case "POLICY_REJECTED":
      return "compareMeasurements";
    default: // ENVELOPE_REJECTED, QUOTE_REJECTED
      return "verifyEnclave";
  }
}

function createPendingVerificationDocument(configRepo: string): VerificationDocument {
  return {
    schemaVersion: VERIFICATION_DOCUMENT_SCHEMA_VERSION,
    configRepo,
    enclaveHost: '',
    releaseDigest: '',
    codeMeasurement: { type: '', registers: [] },
    enclaveMeasurement: { measurement: { type: '', registers: [] } },
    tlsPublicKey: '',
    hpkePublicKey: '',
    codeFingerprint: '',
    enclaveFingerprint: '',
    selectedRouterEndpoint: '',
    securityVerified: false,
    verifier: {
      name: VERIFIER_NAME,
      version: VERIFIER_VERSION,
    },
    steps: {
      fetchDigest: { status: 'pending' },
      verifyCode: { status: 'pending' },
      verifyEnclave: { status: 'pending' },
      compareMeasurements: { status: 'pending' },
    },
  };
}

/**
 * Low-level secure client providing a verified fetch function for custom HTTP requests.
 * 
 * SecureClient performs enclave attestation verification and provides a `fetch` function
 * that encrypts all request bodies end-to-end. Use this when you need direct control
 * over HTTP requests or want to use a different OpenAI client.
 * 
 * For most use cases, prefer {@link TinfoilAI} which wraps this with an OpenAI-compatible API.
 * 
 * @example
 * ```typescript
 * import { SecureClient } from "tinfoil";
 * 
 * const client = new SecureClient();
 * await client.ready();
 * 
 * // Use with OpenAI SDK
 * const openai = new OpenAI({
 *   apiKey: "your-key",
 *   baseURL: client.getBaseURL(),
 *   fetch: client.fetch,
 * });
 * ```
 * 
 * @example
 * ```typescript
 * // Direct fetch for custom requests
 * const response = await client.fetch("/v1/chat/completions", {
 *   method: "POST",
 *   headers: { "Content-Type": "application/json" },
 *   body: JSON.stringify({ model: "llama3-3-70b", messages: [...] }),
 * });
 * ```
 * 
 * @see https://docs.tinfoil.sh/sdk/javascript-sdk
 * @see https://docs.tinfoil.sh/guides/proxy-server - Proxy server setup
 */
export class SecureClient {
  // --- Immutable config (from constructor, never changes) ---
  private readonly config: {
    readonly baseURL?: string;
    readonly enclaveURL?: string;
    readonly configRepo: string;
    readonly transport: TransportMode;
    readonly attestationBundleURL?: string;
    readonly userCacheSecret?: string;
  };

  // --- Derived state (cleared on reset) ---
  private initPromise: Promise<void> | null = null;
  private verificationDocument: VerificationDocument;
  private _transport: SecureTransport | null = null;
  private resolvedEnclaveURL?: string;
  private resolvedBaseURL?: string;
  private attestedTlsPublicKeyFingerprint?: string;

  constructor(options: SecureClientOptions = {}) {
    // Validate provided URLs, including the empty string: URL resolution
    // keeps "" (via ??) rather than falling back, so an unguarded empty value
    // would surface later as a confusing "Invalid URL" instead of a clear error.
    if (options.baseURL !== undefined) {
      let baseURL: URL;
      try {
        baseURL = new URL(options.baseURL);
      } catch (cause) {
        throw new ConfigurationError(`baseURL must be a valid HTTP(S) URL. Got: ${options.baseURL}`, {
          cause: cause as Error,
        });
      }
      if (baseURL.protocol !== "http:" && baseURL.protocol !== "https:") {
        throw new ConfigurationError(`baseURL must be a valid HTTP(S) URL. Got: ${options.baseURL}`);
      }
    }
    if (options.enclaveURL !== undefined && !options.enclaveURL.startsWith("https://")) {
      throw new ConfigurationError(`enclaveURL must use HTTPS. Got: ${options.enclaveURL}`);
    }
    if (options.attestationBundleURL !== undefined && !options.attestationBundleURL.startsWith("https://")) {
      throw new ConfigurationError(`attestationBundleURL must use HTTPS. Got: ${options.attestationBundleURL}`);
    }
    if (options.configRepo && !options.enclaveURL) {
      throw new ConfigurationError("configRepo requires enclaveURL — without it, ATC always uses the default router repo.");
    } else if (options.enclaveURL && !options.configRepo) {
      console.warn(`[tinfoil] No configRepo specified, verifying against "${TINFOIL_CONFIG.DEFAULT_ROUTER_REPO}".`);
    }

    this.config = {
      baseURL: options.baseURL,
      enclaveURL: options.enclaveURL,
      configRepo: options.configRepo ?? TINFOIL_CONFIG.DEFAULT_ROUTER_REPO,
      transport: options.transport || 'ehbp',
      attestationBundleURL: options.attestationBundleURL,
      userCacheSecret: options.userCacheSecret,
    };
    this.verificationDocument = createPendingVerificationDocument(this.config.configRepo);
  }

  /**
   * Wait for the client to complete verification and be ready for requests.
   * 
   * This performs enclave attestation, code verification, and establishes
   * the secure transport. Must be called before using `fetch`.
   * 
   * @throws Error if verification fails
   */
  public async ready(): Promise<void> {
    if (!this.initPromise) {
      this.initPromise = this.initSecureClient().catch(async err => {
        // Only try recovery if the error is transient (network I/O, attestation errors)
        if (err instanceof FetchError || err instanceof AttestationError) {
          this.clearDerivedState(); // Start with a new enclave
          await new Promise(r => setTimeout(r, INIT_RETRY_DELAY_MS));
          return this.initSecureClient().catch(retryErr => {
            this.reset();
            throw retryErr;
          });
        }
        // Everything else (ConfigurationError, bugs) — propagate immediately
        this.reset();
        throw err;
      });
    }
    return this.initPromise;
  }

  /**
   * Clear derived state without touching initPromise (preserves deduplication).
   */
  private clearDerivedState(): void {
    this._transport = null;
    this.verificationDocument = createPendingVerificationDocument(this.config.configRepo);
    this.resolvedEnclaveURL = undefined;
    this.resolvedBaseURL = undefined;
    this.attestedTlsPublicKeyFingerprint = undefined;
  }

  /**
   * Reset the client, clearing all verification state and transport.
   * 
   * After calling reset(), the next call to `ready()` or `fetch()` will
   * perform a fresh attestation and establish a new secure transport.
   * 
   * Use this for retry logic when the enclave may have restarted with new keys,
   * or when you want to force re-verification.
   * 
   * @example
   * ```typescript
   * // Force re-attestation
   * client.reset();
   * await client.ready();
   * 
   * // Or let it re-attest lazily on next request
   * client.reset();
   * await client.fetch("/v1/chat/completions", { ... });
   * ```
   */
  public reset(): void {
    this.initPromise = null;
    this.clearDerivedState();
  }

  private async initSecureClient(): Promise<void> {
    // Resolve enclaveURL: user-provided config takes precedence, otherwise
    // discover a router endpoint. The v3 document travels enclave-to-client,
    // so discovery needs only the router address — no ATC bundle.
    this.resolvedEnclaveURL = this.config.enclaveURL
      ?? `https://${await fetchRouter(this.config.attestationBundleURL)}`;

    // Resolve baseURL: user-provided config takes precedence, otherwise use the enclave API
    this.resolvedBaseURL = this.config.baseURL ?? this.getEnclaveBaseURL();

    if (
      this.config.transport === 'tls' &&
      this.config.baseURL &&
      new URL(this.resolvedBaseURL!).origin !== new URL(this.resolvedEnclaveURL).origin
    ) {
      throw new ConfigurationError("TLS transport requires baseURL to use the verified enclave origin");
    }

    const { tlsFp, hpkeKey } = await this.verifyEnclave(new URL(this.resolvedEnclaveURL).host);
    this.attestedTlsPublicKeyFingerprint = tlsFp;
    this._transport = await this.createTransport(hpkeKey, tlsFp);
  }

  /**
   * v3 attestation flow against the resolved enclave (Go: SecureClient.verifyV3):
   * fresh nonce → fetch the document (evidence + collateral in one request) →
   * verify it offline against the embedded roots → extract the endorsed
   * channel keys. The verification document is captured on success and on
   * every failure path.
   */
  private async verifyEnclave(host: string): Promise<{ tlsFp: string; hpkeKey: string }> {
    const steps: VerificationDocument['steps'] = {
      fetchDigest: { status: 'pending' },
      verifyCode: { status: 'pending' },
      verifyEnclave: { status: 'pending' },
      compareMeasurements: { status: 'pending' },
    };

    try {
      // Fetch phase: the enclave round-trip is the only network request.
      const nonce = randomNonce();
      let docBytes: Uint8Array;
      try {
        docBytes = await fetchAttestation(host, nonce);
        steps.fetchDigest = { status: 'success' };
      } catch (error) {
        steps.fetchDigest = { status: 'failed', error: (error as Error).message };
        throw new FetchError(`Failed to fetch attestation document from ${host}: ${(error as Error).message}`, {
          cause: error as Error,
        });
      }

      // Verify phase: offline, embedded roots. A rejection is attributed to
      // the step matching its layer; unexpected errors propagate untouched.
      let verified: VerifiedDocumentV3;
      try {
        verified = await verifyDocumentV3(docBytes, nonce, this.config.configRepo);
        steps.verifyCode = { status: 'success' };
        steps.verifyEnclave = { status: 'success' };
        steps.compareMeasurements = { status: 'success' };
      } catch (error) {
        if (error instanceof VerificationError) {
          steps[stepForLayer(error.layer)] = { status: 'failed', error: error.message };
          throw new AttestationError(`Attestation verification failed: ${error.message}`, { cause: error });
        }
        steps.otherError = { status: 'failed', error: (error as Error).message };
        throw error;
      }

      // Binding phase: both endorsed channel keys are required (Go mirrors
      // these as "binding:" failures). EHBP binds the channel to the HPKE
      // key; the TLS fingerprint pins the 'tls' transport and WebSockets.
      let tlsFp: string;
      let hpkeKey: string;
      try {
        tlsFp = tlsPublicKeyFP(verified);
        hpkeKey = hpkePublicKey(verified);
      } catch (error) {
        steps.otherError = { status: 'failed', error: `binding: ${(error as Error).message}` };
        throw new AttestationError(`binding: ${(error as Error).message}`, { cause: error as Error });
      }

      // Fingerprints mirror the legacy flow for consumers that display or
      // compare them. TDX fingerprints incorporate the platform registers,
      // which in v3 come from the verified quote itself (already appraised
      // against the endorsed platform measurements).
      const hw: HardwareMeasurement | undefined =
        verified.enclaveMeasurement.type === TDX_GUEST_V2 && verified.enclaveMeasurement.registers.length >= 2
          ? { MRTD: verified.enclaveMeasurement.registers[0], RTMR0: verified.enclaveMeasurement.registers[1] }
          : undefined;
      let codeFingerprint: string;
      let enclaveFingerprint: string;
      try {
        codeFingerprint = await fingerprintFor(verified.codeMeasurement, hw, verified.enclaveMeasurement.type);
        enclaveFingerprint = await fingerprintFor(verified.enclaveMeasurement, hw, verified.enclaveMeasurement.type);
      } catch (error) {
        steps.otherError = { status: 'failed', error: `measurements: ${(error as Error).message}` };
        throw new AttestationError(`measurements: failed to compute fingerprint: ${(error as Error).message}`, {
          cause: error as Error,
        });
      }

      this.verificationDocument = {
        schemaVersion: VERIFICATION_DOCUMENT_SCHEMA_VERSION,
        configRepo: this.config.configRepo,
        enclaveHost: host,
        releaseTag: verified.codeTag,
        releaseDigest: verified.codeDigest,
        codeMeasurement: verified.codeMeasurement,
        enclaveMeasurement: {
          tlsPublicKeyFingerprint: tlsFp,
          hpkePublicKey: hpkeKey,
          measurement: verified.enclaveMeasurement,
        },
        tlsPublicKey: tlsFp,
        hpkePublicKey: hpkeKey,
        ...(hw && { hardwareMeasurement: hw }),
        codeFingerprint,
        enclaveFingerprint,
        selectedRouterEndpoint: host,
        securityVerified: true,
        verifier: { name: VERIFIER_NAME, version: VERIFIER_VERSION },
        verifiedAt: new Date().toISOString(),
        steps,
      };

      return { tlsFp, hpkeKey };
    } catch (error) {
      // Capture the partial document (the success path never throws after
      // the document is assembled).
      this.saveFailedVerificationDocument(steps, host);
      throw error;
    }
  }

  private saveFailedVerificationDocument(steps: VerificationDocument['steps'], host: string): void {
    this.verificationDocument = {
      schemaVersion: VERIFICATION_DOCUMENT_SCHEMA_VERSION,
      configRepo: this.config.configRepo,
      enclaveHost: host,
      releaseDigest: '',
      codeMeasurement: { type: '', registers: [] },
      enclaveMeasurement: { measurement: { type: '', registers: [] } },
      tlsPublicKey: '',
      hpkePublicKey: '',
      codeFingerprint: '',
      enclaveFingerprint: '',
      selectedRouterEndpoint: host,
      securityVerified: false,
      verifier: { name: VERIFIER_NAME, version: VERIFIER_VERSION },
      steps,
    };
  }

  /**
   * Get the verification document containing attestation details.
   * 
   * @returns The verification document with attestation results
   * @see https://docs.tinfoil.sh/verification/attestation-architecture
   */
  public getVerificationDocument(): VerificationDocument {
    return cloneVerificationDocument(this.verificationDocument);
  }

  /**
   * Get the base URL for API requests.
   * 
   * Returns the base URL requests will be sent to.
   */
  public getBaseURL(): string | undefined {
    return this.resolvedBaseURL;
  }

  /**
   * Get the URL of the enclave endpoint, or undefined before ready().
   */
  public getEnclaveURL(): string | undefined {
    return this.resolvedEnclaveURL;
  }

  /**
   * Get the direct API base URL of the enclave, or undefined before ready().
   */
  public getEnclaveBaseURL(): string | undefined {
    return this.resolvedEnclaveURL ? `${this.resolvedEnclaveURL}/v1/` : undefined;
  }

  private async createTransport(hpkePublicKey?: string, tlsPublicKeyFingerprint?: string): Promise<SecureTransport> {
    // The prompt-cache scoping secret: the userCacheSecret option wins, then
    // the TINFOIL_USER_CACHE_SECRET environment variable, then the secret
    // persisted at ~/.tinfoil/user_cache_secret (generated on first use).
    // Empty values fall through to the attempted persisted or generated default.
    const userCacheSecret = await resolveUserCacheSecret(this.config.userCacheSecret);

    if (this.config.transport === 'tls') {
      return await createSecureFetch(this.resolvedBaseURL!, undefined, tlsPublicKeyFingerprint, this.resolvedEnclaveURL, userCacheSecret);
    }

    return await createSecureFetch(this.resolvedBaseURL!, hpkePublicKey, undefined, this.resolvedEnclaveURL, userCacheSecret);
  }

  /**
   * Secure fetch function that encrypts request bodies end-to-end.
   *
   * Use this as a drop-in replacement for global `fetch`. Request bodies are
   * encrypted using HPKE (or TLS pinning if configured) so only the verified
   * enclave can decrypt them.
   *
   * On `KeyConfigMismatchError` (server key rotation), automatically re-attests
   * and retries the request once. All other errors propagate to the caller.
   *
   * @example
   * ```typescript
   * const response = await client.fetch("/v1/chat/completions", {
   *   method: "POST",
   *   headers: { "Content-Type": "application/json" },
   *   body: JSON.stringify({ model: "llama3-3-70b", messages: [...] }),
   * });
   * ```
   */
  get fetch(): typeof fetch {
    return async (input: RequestInfo | URL, init?: RequestInit) => {
      await this.ready();

      try {
        return await this._transport!.fetch(input, init);
      } catch (error) {
        // Channel recovery: server rotated keys, request was never processed — safe to retry
        if (error instanceof KeyConfigMismatchError) {
          this.reset();
          await this.ready();
          return await this._transport!.fetch(input, init);
        }
        throw error;
      }
    };
  }

  /**
   * Returns the session recovery token for the most recent request.
   *
   * The token is overwritten on every request, so it must be captured
   * immediately after the relevant `fetch()` resolves and before issuing
   * another request on this client.
   */
  public async getSessionRecoveryToken(): Promise<SessionRecoveryToken> {
    if (!this._transport) {
      throw new Error('No session recovery token available — call fetch() first');
    }
    return this._transport.getSessionRecoveryToken();
  }

  /**
   * Verifies the WebSocket preconditions and returns the attested TLS
   * public key fingerprint to pin against.
   *
   * WebSockets can't be covered by EHBP (it only seals HTTP bodies), so they
   * are secured by connecting directly to the enclave with the TLS connection
   * pinned to the attested key. That rules out browsers, which do not expose
   * TLS certificate details.
   */
  private async requireWebSocketCapability(): Promise<string> {
    if (isRealBrowser()) {
      throw new ConfigurationError(
        "Verified WebSockets are not supported in browser environments: browsers do not " +
        "expose TLS certificate details, so the connection cannot be pinned to the attested enclave key."
      );
    }
    await this.ready();

    if (!this.attestedTlsPublicKeyFingerprint) {
      throw new AttestationError("Attestation did not include a TLS public key fingerprint");
    }
    return this.attestedTlsPublicKeyFingerprint;
  }

  /**
   * Returns `ws` client options that pin the TLS connection to the attested
   * enclave key, for wiring verified WebSockets into other libraries.
   *
   * Node.js only. Standard certificate chain and hostname validation still
   * apply on top of the pin.
   */
  public async getPinnedWebSocketOptions(): Promise<WS.ClientOptions> {
    const fingerprint = await this.requireWebSocketCapability();
    const { pinnedWsClientOptions } = await import("./pinned-ws.js");
    return pinnedWsClientOptions(fingerprint);
  }

  /**
   * Opens a WebSocket to the verified enclave with the TLS connection pinned
   * to the attested enclave key.
   *
   * Node.js only. Connections are made directly to the verified enclave.
   *
   * The returned socket is a standard `ws` WebSocket in the CONNECTING state;
   * pinning failures surface as an `error` event. A pin failure drops the cached
   * attestation, so the next createWebSocket() re-attests and recovers.
   *
   * @param path - Path (and query) relative to the enclave URL, e.g.
   *   `/v1/realtime?model=voxtral-mini-4b-realtime`
   *
   * @example
   * ```typescript
   * const socket = await client.createWebSocket(
   *   "/v1/realtime?model=voxtral-mini-4b-realtime",
   *   { wsOptions: { headers: { Authorization: `Bearer ${apiKey}` } } },
   * );
   * socket.on("open", () => { ... });
   * ```
   */
  public async createWebSocket(path: string, options?: SecureWebSocketOptions): Promise<WS.WebSocket> {
    const fingerprint = await this.requireWebSocketCapability();

    const enclaveHost = new URL(this.resolvedEnclaveURL!).host;
    const target = new URL(path, this.resolvedEnclaveURL);
    if (target.protocol === "https:") {
      target.protocol = "wss:";
    }
    if (target.protocol !== "wss:") {
      throw new ConfigurationError(`Insecure connection rejected: only wss:// is allowed. Got ${target.toString()}`);
    }
    // The Authorization header would travel to whatever host the URL names,
    // so refuse anything other than the verified enclave.
    if (target.host !== enclaveHost) {
      throw new ConfigurationError(
        `refusing WebSocket connection to ${target.host}: this client is bound to the verified enclave ${enclaveHost}`
      );
    }

    const { createPinnedWebSocket } = await import("./pinned-ws.js");
    const socket = await createPinnedWebSocket(target.toString(), fingerprint, options);

    // The TLS key is cached only for performance; on a pin failure (e.g. the enclave
    // rotated its key) drop it so the next call re-attests against the current key.
    socket.once("error", (err: Error) => {
      if (err instanceof AttestationError) {
        this.reset();
      }
    });

    return socket;
  }
}
