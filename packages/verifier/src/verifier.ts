/**
 * The v3 verifier: parses and binds a document, authenticates its reference
 * values, authenticates the CPU quote, assembles the expected state and
 * validates the quote against it. Each step names the layer that rejects.
 */
import { VERIFIER_NAME, VERIFIER_VERSION } from "./version.js";
import {
  ARTIFACT_FRESHNESS_V1_FORMAT,
  FORMAT_V2,
  FORMAT_V3,
  FRESHNESS_ID_CODE,
  FRESHNESS_ID_PLATFORM,
  FRESHNESS_ID_RUNTIME,
  SIGSTORE_FRESHNESS_V1_FORMAT,
} from "./document/collateral/collateral.js";
import type { ConfigEndorsement } from "./document/collateral/config.js";
import { validateRuntimeReference, type RuntimeReference } from "./document/collateral/runtime.js";
import { InvalidInputError, parse as parseDocument, type Document } from "./document/document.js";
import { UsageError, VerificationError, VerifyError, type Layer } from "./errors.js";
import { sha256, toHex } from "./internal/bytes.js";
import { decodeLowerHex } from "./internal/canonical.js";
import {
  ConfigVerifier,
  FreshnessVerifier,
  KIND_PLATFORM,
  KIND_RUNTIME,
  MAX_CONFIG_SIZE,
  parseConfigName,
  PLATFORM_ARTIFACT_NAME,
  PUBLIC_REGISTRY_ID,
  publicSigningKeys,
  validateConfigPins,
  validateRegistryIDs,
  type ArtifactKind,
  type ConfigPolicy,
} from "./internal/endorsement/approval.js";
import { authenticateFreshness, MAX_FRESHNESS_AGE_MS } from "./internal/endorsement/freshness.js";
import { ProvenanceClient } from "./internal/endorsement/provenance.js";
import { parseReference, type AuthenticatedArtifact } from "./internal/endorsement/reference.js";
import { authenticateRuntime } from "./internal/endorsement/runtime.js";
import { ARTIFACT_FORMAT, ARTIFACT_FORMAT_V2, parse as parseArtifact, type Artifact } from "./internal/policy/artifact.js";
import * as quote from "./internal/quote/quote.js";
import { configRuntime } from "./internal/runtime/config.js";
import { decodeManifest, parseManifest, type Manifest, type Measurements } from "./internal/runtime/manifest.js";
import * as semver from "./internal/semver.js";
import { pinnedKeys, type PinnedKey } from "./internal/sigstore/keyed.js";
import { cloneExpected, REGISTER_SIZE, type Expected } from "./measurement.js";
import { Verification, type ArtifactVerification, type ConfigVerification } from "./verification.js";

/**
 * An exact config the caller trusts without holding its bytes: its digest
 * and the runtime release it pins, optionally with its name. The document's
 * config endorsement is not consulted; the quote must still bind the digest.
 */
export interface EmbeddedConfigReference {
  /** The /org/project/revision name; absent or "" leaves the name unpinned. */
  readonly name?: string;
  /** Lowercase hex SHA-256 of the config bytes. */
  readonly digest: string;
  /** The runtime release the config pins (its `cvm-version`). */
  readonly runtime: RuntimeReference;
}

/** Caller-trusted reference values that replace endorsement checks for the components supplied. */
export interface EmbeddedReferences {
  /** Exact config bytes, optionally with their /org/project/revision name. Exclusive with `configReference`. */
  readonly config?: { readonly name?: string; readonly bytes: Uint8Array };
  /** The config's digest and runtime pin, when the bytes themselves are not disclosed. Exclusive with `config`. */
  readonly configReference?: EmbeddedConfigReference;
  /** The exact runtime manifest the config pins. */
  readonly runtime?: Uint8Array;
  /** A platform-endorsements/v2 policy artifact. */
  readonly platform?: Uint8Array;
}

export interface VerifierOptions {
  /** Registers the enclave must match in addition to the release's. */
  readonly pinnedRegisters?: Expected;
  /** The freshness window; 0 or undefined selects seven days. */
  readonly freshnessMaxAgeMs?: number;
  /** PEM-encoded P-256 public keys that approve configs, replacing Tinfoil's. */
  readonly configSigningKeys?: readonly string[];
  /** PEM-encoded P-256 public keys that approve artifact freshness, replacing Tinfoil's. */
  readonly freshnessSigningKeys?: readonly string[];
  /** Authorizes an unsigned config; throwing rejects the document at the provenance layer. */
  readonly configAuthorizer?: (endorsement: ConfigEndorsement) => void | Promise<void>;
  /**
   * The registry IDs a config approval may be accepted under, replacing
   * public-only trust: an approval certified for another registry rejects.
   * Needs registry trust, so it conflicts with config signing keys, an
   * embedded config and a config authorizer. Must be non-empty without
   * repeats.
   */
  readonly configRegistryIDs?: readonly string[];
  /**
   * Registry IDs accepted alongside the public registry: the accepted set
   * is the public registry ID followed by these. Validated and in conflict
   * like `configRegistryIDs`, which it cannot be combined with. Must be
   * non-empty, canonical and without repeats, the public registry ID
   * included.
   */
  readonly additionalConfigRegistryIDs?: readonly string[];
  readonly embeddedReferences?: EmbeddedReferences;
}

/**
 * Trust roots that replace the embedded production anchors. Only the
 * conformance adapter passes these, through {@link dangerousTestOnlyVerifier};
 * this module's export is not re-exported from the package entry.
 */
export interface DangerousTestOnlyRoots extends quote.VendorRoots {
  /** Sigstore trusted-root JSON. */
  readonly sigstore?: Uint8Array;
  /** PEM-encoded P-256 registry root keys, replacing the public signing keys as config approval and registry roots. */
  readonly registryRoots?: readonly string[];
}

/** An exact config/runtime pair the caller trusts, validated and copied. */
interface ConfigReference {
  readonly name: string;
  readonly digest: string;
  readonly runtime: RuntimeReference;
}

interface Embedded {
  readonly configReference?: ConfigReference;
  readonly runtime?: Uint8Array;
  readonly platform?: Uint8Array;
}

interface Policy {
  readonly embedded: Embedded;
  readonly pinnedRegisters?: Expected;
  readonly freshnessMaxAgeMs: number;
  readonly configAuthorizer?: (endorsement: ConfigEndorsement) => void | Promise<void>;
  readonly configRegistryIDs?: readonly string[];
  readonly configKeysPinned: boolean;
  readonly freshnessKeysPinned: boolean;
}

/** The authenticated reference values of a document and the facts they establish. */
interface References {
  readonly quote: quote.ReferenceValues;
  readonly artifact: ArtifactVerification;
  readonly platform?: ArtifactVerification;
  readonly config?: ConfigVerification;
  readonly freshnessExpiresAt?: Date;
}

/** Only this module holds the token the constructor requires, so a verifier comes from {@link Verifier.create}. */
const BUILT_HERE: unique symbol = Symbol("verifier");
type BuiltHere = typeof BUILT_HERE;

/** The parts a built verifier is made of. */
interface Parts {
  readonly policy: Policy;
  readonly prov: ProvenanceClient;
  readonly configVerifier: ConfigVerifier;
  readonly freshnessVerifier: FreshnessVerifier;
  readonly roots: quote.VendorRoots;
}

/** Appraises v3 attestation documents against a fixed policy. Immutable once built. */
export class Verifier {
  /** The freshness window in milliseconds. */
  readonly freshnessMaxAgeMs: number;
  /**
   * The caller's pinned registers, or undefined. A frozen copy taken when the
   * verifier was built; its register bytes are shared across reads and must
   * not be mutated.
   */
  readonly pinnedRegisters: Expected | undefined;
  /** Whether the caller, rather than an endorsement, authorizes the config. */
  readonly callerAuthorizesConfig: boolean;
  readonly #policy: Policy;
  readonly #prov: ProvenanceClient;
  readonly #configVerifier: ConfigVerifier;
  readonly #freshnessVerifier: FreshnessVerifier;
  readonly #roots: quote.VendorRoots;

  /** @internal Not callable from outside this module: use {@link Verifier.create}. */
  constructor(token: BuiltHere, parts: Parts) {
    if (token !== BUILT_HERE) throw new UsageError("verifier must be built with Verifier.create");
    this.#policy = parts.policy;
    this.#prov = parts.prov;
    this.#configVerifier = parts.configVerifier;
    this.#freshnessVerifier = parts.freshnessVerifier;
    this.#roots = parts.roots;
    this.freshnessMaxAgeMs = parts.policy.freshnessMaxAgeMs;
    this.pinnedRegisters = parts.policy.pinnedRegisters === undefined ? undefined : Object.freeze(cloneExpected(parts.policy.pinnedRegisters));
    this.callerAuthorizesConfig = parts.policy.embedded.configReference !== undefined || parts.policy.configAuthorizer !== undefined;
    // The properties describe the policy the verifier enforces, so neither can be changed after it is built.
    Object.freeze(this);
  }

  /**
   * Builds a verifier. Defaults use the embedded production trust roots,
   * Tinfoil's public signing keys, and a seven-day freshness bound.
   * Throws UsageError for invalid options.
   */
  static async create(options: VerifierOptions = {}): Promise<Verifier> {
    return build(options, {});
  }

  /** Throws UsageError when `repo` cannot be verified under this verifier's policy. */
  checkRepoVerifiability(repo: string): void {
    this.#referencePins(repo);
  }

  /** Appraises a nonce-bound v3 document against the pinned `repo` at the current time. */
  async verifyV3(docBytes: Uint8Array, nonce: Uint8Array, repo: string): Promise<Verification> {
    return this.verifyV3At(docBytes, nonce, repo, new Date());
  }

  /**
   * Like {@link verifyV3}, but `verificationTime` replaces the clock in every
   * time-bound check (freshness, vendor certificate and CRL validity).
   */
  async verifyV3At(docBytes: Uint8Array, nonce: Uint8Array, repo: string, verificationTime: Date): Promise<Verification> {
    if (!(verificationTime instanceof Date) || !Number.isFinite(verificationTime.getTime())) {
      throw new UsageError("verification time must be a valid date");
    }
    const now = new Date(verificationTime.getTime());

    const doc = await at("envelope", async () => {
      try {
        return await parseDocument(docBytes, nonce);
      } catch (err) {
        if (err instanceof InvalidInputError) throw new UsageError(err.message, { cause: err });
        throw err;
      }
    });

    const refs = await at("provenance", async () => {
      switch (doc.collateralFormat()) {
        case FORMAT_V3:
          return this.#configReferences(doc, repo, now);
        case FORMAT_V2:
          return this.#codeReferences(doc, repo, now);
        default:
          throw new Error(`unsupported collateral format ${JSON.stringify(doc.collateralFormat())}`);
      }
    });

    const authenticated = await at("quote", () =>
      quote.authenticate(doc.cpuEvidence(), doc.cpuEndorsements(), now, { dangerousTestOnlyRoots: this.#roots }),
    );

    const assembled = await at("policy", () => quote.assemble(doc, refs.quote, this.#policy.pinnedRegisters, authenticated));
    await at("policy", () => quote.validate(assembled));

    return new Verification({
      configRepo: refs.artifact.repo,
      codeDigest: refs.artifact.digest,
      codeTag: refs.artifact.tag,
      codeMeasurement: assembled.codeMeasurement,
      enclaveMeasurement: authenticated.measurement,
      cryptoMaterial: doc.cryptoMaterialItems(),
      config: refs.config,
      runtime: refs.config === undefined ? undefined : refs.artifact,
      platform: refs.platform,
      freshnessExpiresAt: refs.freshnessExpiresAt,
      metadata: { verifier: { name: VERIFIER_NAME, version: VERIFIER_VERSION }, verifiedAt: now },
    });
  }

  // ---------------------------------------------------------------- code releases (collateral v2)

  #requiresConfigCollateral(): boolean {
    const e = this.#policy.embedded;
    return (
      e.configReference !== undefined ||
      e.runtime !== undefined ||
      e.platform !== undefined ||
      this.#policy.configKeysPinned ||
      this.#policy.freshnessKeysPinned ||
      this.#policy.configAuthorizer !== undefined ||
      this.#policy.configRegistryIDs !== undefined
    );
  }

  async #codeReferences(doc: Document, repo: string, now: Date): Promise<References> {
    if (this.#requiresConfigCollateral()) throw new Error(`configured trust requires ${FORMAT_V3}`);
    const codeRef = doc.sigstoreCode();
    const pin = usage(() => parseReference(repo));
    const code = await this.#prov.authenticateCode(codeRef.bundle, pin, codeRef.tag, codeRef.digest);
    const platformRef = doc.sigstorePlatform();
    let endorsements;
    try {
      endorsements = await this.#prov.authenticatePlatformEndorsements(platformRef.bundle, platformRef.repo, platformRef.tag, platformRef.digest, ARTIFACT_FORMAT);
    } catch (err) {
      throw new Error(`verifying platform endorsements: ${message(err)}`);
    }
    const codeWitnessedAt = await this.#witnessedAt(doc, FRESHNESS_ID_CODE, "code", code, now);
    const platformWitnessedAt = await this.#witnessedAt(doc, FRESHNESS_ID_PLATFORM, "platform", endorsements, now);
    return {
      quote: { kind: "legacy", endorsements: endorsements.artifact, sevSnp: code.sevSnp, tdx: code.tdx, shape: code.shape },
      artifact: artifactVerification(code),
      freshnessExpiresAt: freshnessExpiration(this.#policy.freshnessMaxAgeMs, codeWitnessedAt, platformWitnessedAt),
    };
  }

  /** The log time of the freshness witness with the given id, which must endorse `artifact`. */
  async #witnessedAt(doc: Document, id: string, what: string, artifact: AuthenticatedArtifact, now: Date): Promise<Date> {
    try {
      const freshness = doc.freshness(id);
      if (freshness.format !== SIGSTORE_FRESHNESS_V1_FORMAT) {
        throw new Error(`legacy verification requires freshness collateral format ${JSON.stringify(SIGSTORE_FRESHNESS_V1_FORMAT)}`);
      }
      return await authenticateFreshness(this.#prov, freshness.bundle, artifact, now, this.#policy.freshnessMaxAgeMs);
    } catch (err) {
      throw new Error(`verifying ${what} freshness: ${message(err)}`);
    }
  }

  // ---------------------------------------------------------------- config-pinned runtimes (collateral v3)

  /**
   * The config pins `repo` imposes, as a config policy without a clock. The
   * accepted registry IDs are the caller's, or the public registry alone
   * under the registry roots; caller-pinned keys leave the registry ID
   * unpinned.
   */
  #referencePins(ref: string): ConfigPins {
    let registryIDs = this.#policy.configRegistryIDs;
    if (registryIDs === undefined && !this.#policy.configKeysPinned) registryIDs = [PUBLIC_REGISTRY_ID];
    const pins: ConfigPins = { identity: "", revision: "", digest: "", registryIDs };
    if (this.#policy.configAuthorizer !== undefined && ref !== "") {
      throw new UsageError("config authorizer cannot authenticate repository or revision pins; enforce them in caller policy");
    }
    let pinned = pins;
    if (ref !== "") {
      const parsed = usage(() => parseReference(ref));
      pinned = { ...pins, identity: "/" + parsed.repo, revision: parsed.tag, digest: parsed.digest };
    }
    const embedded = this.#policy.embedded.configReference;
    if (embedded !== undefined) {
      let identity = "";
      let revision = "";
      if (embedded.name !== "") ({ identity, revision } = usage(() => parseConfigName(embedded.name)));
      if (
        (pinned.identity !== "" && pinned.identity !== identity) ||
        (pinned.revision !== "" && pinned.revision !== revision) ||
        (pinned.digest !== "" && pinned.digest !== embedded.digest)
      ) {
        throw new UsageError("embedded config does not match the caller's pins");
      }
    }
    return pinned;
  }

  async #configReferences(doc: Document, repo: string, now: Date): Promise<References> {
    const pins = this.#referencePins(repo);
    // Config identities and revisions are stricter than the repository
    // references legacy collateral accepts, so only config collateral checks
    // them; a pin that can never match is the caller's mistake.
    if (pins.identity !== "") usage(() => validateConfigPins({ ...pins, now, maxAgeMs: 0, futureSkewMs: 0 }));
    const { expected, config } = await this.#resolveConfig(doc, pins, now);
    const digest = decodeLowerHex("config digest", config.digest, 32);
    const { manifest, artifact } = await this.#resolveRuntime(doc, expected, now);
    const { platform, platformArtifact } = await this.#resolvePlatform(doc, now);
    const runtime: Measurements = manifest.measurements ?? { formatVersion: 0n };
    return {
      quote: { kind: "config", endorsements: platform, runtime, hash: digest },
      artifact,
      platform: platformArtifact,
      config,
      freshnessExpiresAt: freshnessExpiration(this.#policy.freshnessMaxAgeMs, config.approvalTime, platformArtifact.approvalTime, artifact.approvalTime),
    };
  }

  /** The runtime the config pins, and what established the config. */
  async #resolveConfig(doc: Document, pins: ConfigPins, now: Date): Promise<{ expected: RuntimeReference; config: ConfigVerification }> {
    const embedded = this.#policy.embedded.configReference;
    if (embedded !== undefined) {
      return {
        expected: embedded.runtime,
        config: { source: "embedded", name: embedded.name, digest: embedded.digest, reference: "", signingKeyHint: "", registryID: "" },
      };
    }
    const material = doc.configEndorsement();
    const authorizer = this.#policy.configAuthorizer;
    if (authorizer !== undefined) {
      const config = material.config ?? new Uint8Array();
      if (config.length === 0 || config.length > MAX_CONFIG_SIZE) throw new Error("config size is outside allowed bounds");
      try {
        await authorizer({ ...material, config: config.slice(), ...(material.issuer === undefined ? {} : { issuer: material.issuer.slice() }) });
      } catch (err) {
        throw new VerificationError("provenance", `authorizing config: ${message(err)}`, { cause: err });
      }
      const digest = toHex(await sha256(config));
      return { expected: configRuntime(config), config: { source: "policy", name: "", digest, reference: "", signingKeyHint: "", registryID: "" } };
    }
    if (material.bundle === undefined) throw new Error("unsigned config requires a config authorizer");
    const policy: ConfigPolicy = {
      identity: pins.identity,
      revision: pins.revision,
      digest: pins.digest,
      now,
      maxAgeMs: this.#policy.freshnessMaxAgeMs,
      futureSkewMs: 0,
      ...(pins.registryIDs === undefined ? {} : { registryIDs: pins.registryIDs }),
    };
    let approved;
    try {
      // An issuer certificate selects the certified path under the registry
      // roots; caller-pinned keys ignore it and verify the key-signed bundle.
      approved =
        material.issuer !== undefined && !this.#policy.configKeysPinned
          ? await this.#configVerifier.verifyCertified(material.config, material.bundle, material.issuer, policy)
          : await this.#configVerifier.verify(material.config, material.bundle, policy);
    } catch (err) {
      throw new Error(`verifying config approval: ${message(err)}`);
    }
    if (material.reference !== approved.reference) throw new Error("config endorsement reference does not match the verified approval");
    let expected: RuntimeReference;
    if (approved.runtime !== undefined) {
      expected = approved.runtime;
    } else {
      if (material.config === undefined) throw new Error("config endorsement without config bytes must pin a runtime");
      expected = configRuntime(material.config);
    }
    return {
      expected,
      config: {
        source: "endorsement",
        name: approved.name,
        digest: approved.digest,
        reference: approved.reference,
        signingKeyHint: approved.signingKeyHint,
        approvalTime: approved.approvalTime,
        registryID: approved.registryID,
        ...(approved.signatureTime === undefined ? {} : { signatureTime: approved.signatureTime }),
      },
    };
  }

  async #resolveRuntime(doc: Document, expected: RuntimeReference, now: Date): Promise<{ manifest: Manifest; artifact: ArtifactVerification }> {
    const embedded = this.#policy.embedded.runtime;
    if (embedded !== undefined) {
      const manifest = await parseManifest(embedded, expected);
      return {
        manifest,
        artifact: { source: "embedded", repo: expected.repo, tag: semver.canonical(expected.tag), digest: expected.digest, name: "", commit: "" },
      };
    }
    const material = doc.runtime();
    const authenticated = await authenticateRuntime(this.#prov, material, expected);
    const approvedAt = await this.#approvedAt(doc, FRESHNESS_ID_RUNTIME, KIND_RUNTIME, "runtime", authenticated, now);
    return { manifest: authenticated.manifest, artifact: artifactVerification(authenticated, approvedAt) };
  }

  async #resolvePlatform(doc: Document, now: Date): Promise<{ platform: Artifact; platformArtifact: ArtifactVerification }> {
    const embedded = this.#policy.embedded.platform;
    if (embedded !== undefined) {
      return {
        platform: parseArtifact(embedded),
        platformArtifact: { source: "embedded", repo: "", tag: "", digest: toHex(await sha256(embedded)), name: "", commit: "" },
      };
    }
    const material = doc.configPlatform();
    const platform = await this.#prov.authenticatePlatformEndorsements(material.bundle, material.repo, material.tag, material.digest, ARTIFACT_FORMAT_V2);
    if (platform.subjectName !== PLATFORM_ARTIFACT_NAME) throw new Error("config verification requires its dedicated platform endorsement artifact");
    const approvedAt = await this.#approvedAt(doc, FRESHNESS_ID_PLATFORM, KIND_PLATFORM, "platform", platform, now);
    return { platform: platform.artifact, platformArtifact: artifactVerification(platform, approvedAt) };
  }

  /** The approval time of the artifact-freshness approval with the given id, which must cover `artifact`. */
  async #approvedAt(doc: Document, id: string, kind: ArtifactKind, what: string, artifact: AuthenticatedArtifact, now: Date): Promise<Date> {
    try {
      const material = doc.freshness(id);
      if (material.format !== ARTIFACT_FRESHNESS_V1_FORMAT) throw new Error("config verification requires Tinfoil artifact freshness approvals");
      const approved = await this.#freshnessVerifier.verify(material.bundle, {
        artifact: { kind, repo: artifact.repo, tag: artifact.tag, name: artifact.subjectName, digest: artifact.digest },
        now,
        maxAgeMs: this.#policy.freshnessMaxAgeMs,
        futureSkewMs: 0,
      });
      return approved.approvalTime;
    } catch (err) {
      throw new Error(`verifying ${what} freshness: ${message(err)}`);
    }
  }
}

/** Builds a verifier that trusts the injected roots instead of the embedded ones. */
export function dangerousTestOnlyVerifier(roots: DangerousTestOnlyRoots, options: VerifierOptions = {}): Promise<Verifier> {
  return build(options, roots);
}

/** Validates every option, resolves the trust material and assembles the verifier. */
async function assemble(options: VerifierOptions, roots: DangerousTestOnlyRoots): Promise<Verifier> {
  const prov = roots.sigstore ? await ProvenanceClient.fromJSON(roots.sigstore) : await ProvenanceClient.default();
  const pinnedRegisters = options.pinnedRegisters === undefined ? undefined : validPins(options.pinnedRegisters);
  const freshnessMaxAgeMs = freshnessBound(options.freshnessMaxAgeMs);
  const configKeys = options.configSigningKeys === undefined ? undefined : await keysOf("config signing keys", options.configSigningKeys);
  const freshnessKeys = options.freshnessSigningKeys === undefined ? undefined : await keysOf("freshness signing keys", options.freshnessSigningKeys);
  if (options.configAuthorizer !== undefined && typeof options.configAuthorizer !== "function") {
    throw new UsageError("config authorizer must be a function");
  }
  const embedded = options.embeddedReferences === undefined ? {} : await embeddedOf(options.embeddedReferences);
  if (embedded.configReference !== undefined && configKeys !== undefined) {
    throw new UsageError("embedded config and config signing keys select conflicting trust sources");
  }
  if (options.configAuthorizer !== undefined && (embedded.configReference !== undefined || configKeys !== undefined)) {
    throw new UsageError("config authorizer conflicts with embedded config or config signing keys");
  }
  const configRegistryIDs = registryPolicyOf(options);
  if (configRegistryIDs !== undefined && (embedded.configReference !== undefined || options.configAuthorizer !== undefined)) {
    throw new UsageError("config authority pins require endorsement verification");
  }
  if (configRegistryIDs !== undefined && configKeys !== undefined) {
    throw new UsageError("config registry ID policy requires Tinfoil registry root verification");
  }
  if (embedded.runtime !== undefined && embedded.platform !== undefined && freshnessKeys !== undefined) {
    throw new UsageError("freshness signing keys have no endorsed artifact to verify");
  }
  const publicKeys = await publicSigningKeys();
  // Without caller-pinned config keys, the public keys are the registry
  // roots as well: they issue the signing certificates of certified approvals.
  const registryKeys = roots.registryRoots === undefined ? publicKeys : await keysOf("registry roots", roots.registryRoots);
  const configVerifier = configKeys === undefined ? new ConfigVerifier(prov.root, registryKeys, registryKeys) : new ConfigVerifier(prov.root, configKeys);
  const freshnessVerifier = new FreshnessVerifier(prov.root, freshnessKeys ?? publicKeys);
  const policy: Policy = {
    embedded,
    pinnedRegisters,
    freshnessMaxAgeMs,
    configAuthorizer: options.configAuthorizer,
    configRegistryIDs,
    configKeysPinned: configKeys !== undefined,
    freshnessKeysPinned: freshnessKeys !== undefined,
  };
  return new Verifier(BUILT_HERE, { policy, prov, configVerifier, freshnessVerifier, roots: { amd: roots.amd, intel: roots.intel } });
}

/** Validates the options and assembles the verifier; any failure is a UsageError. */
async function build(options: VerifierOptions, roots: DangerousTestOnlyRoots): Promise<Verifier> {
  try {
    return await assemble(options, roots);
  } catch (err) {
    if (err instanceof UsageError) throw err;
    throw new UsageError(message(err), { cause: err });
  }
}

interface ConfigPins {
  readonly identity: string;
  readonly revision: string;
  readonly digest: string;
  readonly registryIDs?: readonly string[];
}

/**
 * The accepted registry IDs the options pin, or undefined for the default:
 * the caller's exact list, or the public registry plus the additional ones.
 * Giving both is a usage error.
 */
function registryPolicyOf(options: VerifierOptions): readonly string[] | undefined {
  const exact = options.configRegistryIDs === undefined ? undefined : usage(() => registryIDsOf(options.configRegistryIDs!));
  if (options.additionalConfigRegistryIDs === undefined) return exact;
  const additional = usage(() => additionalRegistryIDsOf(options.additionalConfigRegistryIDs!));
  if (exact !== undefined) throw new UsageError("config registry IDs must be supplied once");
  return additional;
}

/** Validates and copies the caller's registry ID list. */
function registryIDsOf(registryIDs: readonly string[]): readonly string[] {
  if (!Array.isArray(registryIDs) || registryIDs.some((s) => typeof s !== "string")) throw new Error("config registry IDs must be a list of strings");
  validateRegistryIDs(registryIDs);
  return [...registryIDs];
}

/** The public registry ID followed by the caller's additional registry IDs, validated as one list. */
function additionalRegistryIDsOf(registryIDs: readonly string[]): readonly string[] {
  if (!Array.isArray(registryIDs) || registryIDs.some((s) => typeof s !== "string")) {
    throw new Error("additional config registry IDs must be a list of strings");
  }
  if (registryIDs.length === 0) throw new Error("additional config registry IDs must not be empty");
  return registryIDsOf([PUBLIC_REGISTRY_ID, ...registryIDs]);
}

/** Runs one pipeline step; an error that is not already classified is attributed to `layer`. */
async function at<T>(layer: Layer, step: () => Promise<T>): Promise<T> {
  try {
    return await step();
  } catch (err) {
    if (err instanceof VerifyError) throw err;
    throw new VerificationError(layer, message(err), { cause: err });
  }
}

/** Runs a caller-input check; its failure is a UsageError. */
function usage<T>(check: () => T): T {
  try {
    return check();
  } catch (err) {
    if (err instanceof VerifyError) throw err;
    throw new UsageError(message(err), { cause: err });
  }
}

function artifactVerification(artifact: AuthenticatedArtifact, approvalTime?: Date): ArtifactVerification {
  return {
    source: "endorsement",
    repo: artifact.repo,
    tag: artifact.tag,
    digest: artifact.digest,
    name: artifact.subjectName,
    commit: artifact.commit,
    ...(approvalTime === undefined ? {} : { approvalTime }),
  };
}

/** The earliest of the given times plus the window; undefined when none is set. */
function freshnessExpiration(maxAgeMs: number, ...times: (Date | undefined)[]): Date | undefined {
  let first: Date | undefined;
  for (const t of times) {
    if (t !== undefined && (first === undefined || t.getTime() < first.getTime())) first = t;
  }
  return first === undefined ? undefined : new Date(first.getTime() + maxAgeMs);
}

function validPins(pins: Expected): Expected {
  const registers: (Uint8Array | undefined)[] =
    pins.platform === "sev-snp" ? [pins.launch] : pins.platform === "tdx" ? [pins.mrtd, pins.rtmr0, pins.rtmr1, pins.rtmr2, pins.rtmr3] : [];
  if (registers.length === 0) throw new UsageError("pinned registers must be an SEV-SNP or TDX expectation");
  for (const r of registers) {
    if (r !== undefined && !(r instanceof Uint8Array && r.length === REGISTER_SIZE)) {
      throw new UsageError(`pinned registers must be ${REGISTER_SIZE} bytes each`);
    }
  }
  return cloneExpected(pins);
}

function freshnessBound(maxAgeMs: number | undefined): number {
  if (maxAgeMs === undefined || maxAgeMs === 0) return MAX_FRESHNESS_AGE_MS;
  if (!Number.isFinite(maxAgeMs) || maxAgeMs < 0) throw new UsageError("freshness maximum age must be a finite, non-negative number");
  return maxAgeMs;
}

async function keysOf(what: string, pems: readonly string[]): Promise<PinnedKey[]> {
  if (pems.length === 0) throw new UsageError(`${what} must not be empty`);
  try {
    return await pinnedKeys(pems);
  } catch (err) {
    throw new UsageError(`${what}: ${message(err)}`, { cause: err });
  }
}

/**
 * Validates the embedded references and settles the config reference: the
 * caller's own, or one derived from embedded config bytes. Both come from
 * the caller, so a runtime manifest the reference does not pin is rejected
 * here rather than at verification.
 */
async function embeddedOf(refs: EmbeddedReferences): Promise<Embedded> {
  if (refs.config === undefined && refs.configReference === undefined && refs.runtime === undefined && refs.platform === undefined) {
    throw new UsageError("embedded references must contain at least one component");
  }
  if (refs.config !== undefined && refs.configReference !== undefined) {
    throw new UsageError("embedded config bytes and reference are mutually exclusive");
  }
  let configReference: ConfigReference | undefined;
  if (refs.config !== undefined) {
    // Copied once so the digest and the runtime pin come from the same bytes, whatever the caller does to its buffer meanwhile.
    const bytes = refs.config.bytes.slice();
    configReference = { name: refs.config.name ?? "", digest: toHex(await sha256(bytes)), runtime: usage(() => configRuntime(bytes)) };
  } else if (refs.configReference !== undefined) {
    configReference = usage(() => configReferenceOf(refs.configReference!));
  }
  if (configReference !== undefined) {
    const reference = configReference;
    if (reference.name !== "") usage(() => parseConfigName(reference.name));
    usage(() => decodeLowerHex("config digest", reference.digest, 32));
    usage(() => validateRuntimeReference(reference.runtime));
    if (refs.runtime !== undefined) await parseManifest(refs.runtime, reference.runtime);
  }
  if (refs.runtime !== undefined) decodeManifest(refs.runtime);
  if (refs.platform !== undefined && parseArtifact(refs.platform).format !== ARTIFACT_FORMAT_V2) {
    throw new UsageError("embedded platform requires platform-endorsements/v2");
  }
  return {
    ...(configReference === undefined ? {} : { configReference }),
    ...(refs.runtime === undefined ? {} : { runtime: refs.runtime.slice() }),
    ...(refs.platform === undefined ? {} : { platform: refs.platform.slice() }),
  };
}

/** A copy of the caller's config reference with every field a string; validation follows. */
function configReferenceOf(ref: EmbeddedConfigReference): ConfigReference {
  const name = ref.name ?? "";
  const runtime = ref.runtime as Partial<RuntimeReference> | undefined;
  if (
    typeof name !== "string" ||
    typeof ref.digest !== "string" ||
    typeof runtime !== "object" ||
    runtime === null ||
    typeof runtime.repo !== "string" ||
    typeof runtime.tag !== "string" ||
    typeof runtime.digest !== "string"
  ) {
    throw new Error("embedded config reference requires a string name, digest and runtime reference");
  }
  return { name, digest: ref.digest, runtime: { repo: runtime.repo, tag: runtime.tag, digest: runtime.digest } };
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
