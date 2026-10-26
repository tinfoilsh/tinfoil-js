import type { VerifierOptions } from "@tinfoilsh/verifier";
import type { SessionRecoveryToken } from "ehbp";
import { SecureClient, configuredVerifier, validateReference, waitFor, type VerificationSnapshot } from "./secure-client.js";
import { ConfigurationError, AttestationError, NetworkError, isBindingRejection, recoveryFailure } from "./errors.js";
import { acquireBytes, copyAcquisitionOptions, httpURL, type AcquisitionOptions } from "./acquisition.js";
import { copyVerificationOptions } from "./client.js";
import { prepareRequest, discard } from "./request.js";
import { shapeGatewayRequest, rankHosts } from "./gateway-request.js";
import { resolveUserCacheSecret } from "./user-cache-secret.js";
export interface CatalogEntry { repo: string; hosts: readonly string[] }
export type Catalog = Readonly<Record<string, CatalogEntry>>;
export interface ModelPin { reference: string; verification?: VerifierOptions }
export interface GatewayOptions {
  catalog?: () => Catalog | Promise<Catalog>;
  pins?: Readonly<Record<string, string | ModelPin>>;
  pinnedOnly?: boolean;
  verification?: VerifierOptions;
  acquisition?: AcquisitionOptions;
  userCacheSecret?: string;
}
interface Policy { reference: string; pinnedModel: string; verification?: VerifierOptions; hosts: string[] }
interface Replica { client: SecureClient; reference: string; pinnedModel: string; models: Set<string> }
function host(value: string): string {
  if (typeof value !== "string" || /[\s/?#@]/.test(value) || value.includes("://")) throw new ConfigurationError("Gateway replica must be a hostname with an optional port");
  const parsed = httpURL(`https://${value}`, "replica", true);
  if (parsed.host !== value) throw new ConfigurationError("Gateway replica must be a canonical hostname");
  return value;
}
function usable(entry: unknown): entry is CatalogEntry {
  if (!entry || typeof entry !== "object") return false;
  const e = entry as CatalogEntry;
  if (typeof e.repo !== "string" || !/^tinfoilsh\/[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(e.repo) || !Array.isArray(e.hosts) || !e.hosts.length) return false;
  try { e.hosts.forEach(host); return true; } catch { return false; }
}
/** An untrusted catalog chooses candidates; caller policy authenticates each replica. */
export class Gateway {
  readonly #baseURL: string;
  readonly #options: Readonly<GatewayOptions>;
  readonly #pins = new Map<string, ModelPin>();
  readonly #replicas = new Map<string, Replica>();
  readonly #affinity = new Map<string, string>();
  #catalog?: Catalog;
  #catalogWork?: Promise<Catalog>;
  #secret?: Promise<string>;
  #selected?: SecureClient;
  #lastRequestClient?: SecureClient;
  constructor(baseURL: string, options: GatewayOptions = {}) {
    this.#baseURL = httpURL(baseURL, "gateway baseURL", true).toString();
    for (const key of ["enclaveURL", "configRepo", "baseURL", "transport"]) if ((options as Record<string, unknown>)[key] !== undefined && !(key === "transport" && (options as Record<string, unknown>)[key] === "ehbp")) throw new ConfigurationError("A gateway selects enclaves and references from its catalog and requires EHBP");
    if (options.verification?.configAuthorizer) throw new ConfigurationError("Gateway model references cannot be combined with a config authorizer");
    configuredVerifier(options.verification);
    for (const [model, value] of Object.entries(options.pins ?? {})) {
      if (!model.trim()) throw new ConfigurationError("Pinned model must not be empty or whitespace");
      const pin = typeof value === "string" ? { reference: value } : value;
      if (!pin || typeof pin.reference !== "string") throw new ConfigurationError("Invalid model pin");
      validateReference(pin.reference);
      if (!pin.reference.startsWith("tinfoilsh/")) throw new ConfigurationError("Gateway pins must name the tinfoilsh owner");
      if (pin.verification?.configAuthorizer) throw new ConfigurationError("Gateway model pins cannot be combined with a config authorizer");
      configuredVerifier(pin.verification);
      this.#pins.set(model, { reference: pin.reference, verification: copyVerificationOptions(pin.verification) });
    }
    if (options.pinnedOnly && !this.#pins.size) throw new ConfigurationError("Pinned-only mode requires at least one model pin");
    this.#options = Object.freeze({ ...options, pins: undefined, acquisition: copyAcquisitionOptions(options.acquisition), verification: copyVerificationOptions(options.verification) });
  }
  async #readCatalog(): Promise<Catalog> {
    if (this.#options.catalog) {
      const snapshot = await this.#options.catalog();
      return this.#catalog = snapshot && typeof snapshot === "object" ? Object.fromEntries(Object.entries(snapshot).map(([key, entry]) => [key, entry && { ...entry, hosts: Array.isArray(entry.hosts) ? [...entry.hosts] : entry.hosts }])) : {};
    }
    if (this.#catalog) return this.#catalog;
    if (!this.#catalogWork) {
      this.#catalogWork = (async () => {
        const bytes = await acquireBytes(new URL("/catalog", this.#baseURL), this.#options.acquisition);
        let value: unknown;
        try { value = JSON.parse(new TextDecoder().decode(bytes)); } catch (cause) { throw new NetworkError("Invalid gateway catalog", { cause }); }
        if (!value || typeof value !== "object" || Array.isArray(value)) throw new NetworkError("Invalid gateway catalog");
        return this.#catalog = Object.fromEntries(Object.entries(value).filter(([, entry]) => usable(entry))) as Catalog;
      })();
      void this.#catalogWork.catch(() => { this.#catalogWork = undefined; });
    }
    return this.#catalogWork;
  }
  #policy(model: string, catalog: Catalog): Policy {
    const pin = this.#pins.get(model);
    if (this.#options.pinnedOnly && !pin) throw new ConfigurationError(`Model ${model} is not pinned`);
    const entry = catalog[model];
    if (!usable(entry)) throw new ConfigurationError(`Model ${model} has no usable gateway catalog entry`);
    if (pin && pin.reference.split("@")[0] !== entry.repo) throw new AttestationError(`Model ${model} requires ${pin.reference.split("@")[0]}; catalog offered ${entry.repo}`);
    return { reference: pin?.reference ?? entry.repo, pinnedModel: pin ? model : "", verification: pin?.verification ?? this.#options.verification, hosts: [...entry.hosts] };
  }
  #replica(target: string, policy: Policy, model: string): SecureClient {
    target = host(target);
    const key = JSON.stringify([target, policy.reference, policy.pinnedModel]);
    let replica = this.#replicas.get(key);
    if (!replica) {
      const client = new SecureClient({ enclaveURL: `https://${target}`, configRepo: policy.reference, verification: policy.verification, baseURL: this.#baseURL, attestationRelayURL: this.#baseURL, acquisition: this.#options.acquisition });
      replica = { client, reference: policy.reference, pinnedModel: policy.pinnedModel, models: new Set() };
      this.#replicas.set(key, replica);
    }
    replica.models.add(model);
    return replica.client;
  }
  async ready(model?: string): Promise<void> {
    if (model === undefined) {
      if (!this.#selected) throw new ConfigurationError("Gateway readiness requires a model before any replica has been selected");
      await this.#selected.ready(); return;
    }
    const policy = this.#policy(model, await this.#readCatalog());
    let failure: unknown;
    for (const target of await rankHosts(policy.hosts, "")) {
      try {
        const client = this.#replica(target, policy, model);
        await client.ready(); this.#selected = client; return;
      } catch (error) {
        if (!(error instanceof AttestationError || error instanceof NetworkError)) throw error;
        failure = error;
      }
    }
    throw failure;
  }
  getBaseURL(): string { return this.#baseURL; }
  inspect(): VerificationSnapshot | undefined { return this.#selected?.inspect(); }
  /** Passive eligibility against the most recently observed catalog. */
  serves(model: string): boolean { try { this.#policy(model, this.#catalog ?? {}); return true; } catch { return false; } }
  replicas(): ReadonlyArray<{ endpoint: string; reference: string; pinnedModel: string; models: readonly string[]; snapshot?: VerificationSnapshot }> {
    return [...this.#replicas.values()].map(replica => Object.freeze({ endpoint: replica.client.getEnclaveURL(), reference: replica.reference, pinnedModel: replica.pinnedModel, models: Object.freeze([...replica.models]), snapshot: replica.client.inspect() }));
  }
  readonly fetch: typeof fetch = async (input, init) => {
    const request = prepareRequest(input, init, this.#baseURL);
    request.init.signal?.throwIfAborted();
    this.#secret ??= resolveUserCacheSecret(this.#options.userCacheSecret);
    await shapeGatewayRequest(request, await this.#secret);
    const headers = new Headers(request.init.headers);
    const model = headers.get("X-Tinfoil-Model") ?? "";
    const policy = this.#policy(model, await waitFor(this.#readCatalog(), request.init.signal));
    const prefix = headers.get("X-Tinfoil-Cache-Prefix") ?? "";
    const affinityKey = JSON.stringify([policy.reference, policy.pinnedModel, prefix]);
    let client: SecureClient | undefined, failure: unknown;
    for (const target of await rankHosts(policy.hosts, prefix, this.#affinity.get(affinityKey))) {
      try { const candidate = this.#replica(target, policy, model); await candidate.ready({ signal: request.init.signal ?? undefined }); client = candidate; break; }
      catch (error) { if (!(error instanceof AttestationError || error instanceof NetworkError)) throw error; failure = error; }
    }
    if (!client) throw failure;
    let rotationFailure: unknown;
    for (let reseals = 0, rotations = 0; ; ) {
      request.init.signal?.throwIfAborted();
      const target = new URL(client.getEnclaveURL()).host;
      headers.set("X-Tinfoil-Seal", target);
      this.#selected = client; this.#lastRequestClient = client;
      let response: Response;
      try { response = await client.fetch(request.url, { ...request.init, headers }); }
      catch (error) {
        if (!isBindingRejection(error) || !request.replayable || rotations++ >= 1) throw rotationFailure ? recoveryFailure(error, rotationFailure) : error;
        rotationFailure = error;
        try { await client.ready({ signal: request.init.signal ?? undefined }); }
        catch (terminal) { throw recoveryFailure(terminal, error); }
        continue;
      }
      const redirected = response.headers.get("X-Tinfoil-Seal");
      if (response.status !== 412 || !redirected || redirected === target || !request.replayable) return response;
      await discard(response);
      if (reseals++ >= 3) throw new NetworkError("Gateway repeatedly routed away from the sealed enclave");
      try { client = this.#replica(redirected, policy, model); await client.ready({ signal: request.init.signal ?? undefined }); }
      catch (cause) {
        if (cause instanceof AttestationError) throw new AttestationError(`Gateway target ${redirected} failed verification`, { cause });
        if (cause instanceof NetworkError) throw new NetworkError(`Gateway target ${redirected} could not be reached`, { cause });
        throw cause;
      }
      if (prefix) this.#affinity.set(affinityKey, redirected);
    }
  };
  async getSessionRecoveryToken(): Promise<SessionRecoveryToken> {
    if (!this.#lastRequestClient) throw new ConfigurationError("No request has supplied a session recovery token");
    return this.#lastRequestClient.getSessionRecoveryToken();
  }
}
