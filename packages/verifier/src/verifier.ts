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
import { sha256, toHex, utf8 } from "./internal/bytes.js";
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
import { strictParse } from "./internal/json/index.js";
import { ARTIFACT_FORMAT, ARTIFACT_FORMAT_V2, parse as parseArtifact, type Artifact } from "./internal/policy/artifact.js";
import * as quote from "./internal/quote/quote.js";
import { configRuntime } from "./internal/runtime/config.js";
import { decodeManifest, parseManifest, type Manifest, type Measurements } from "./internal/runtime/manifest.js";
import * as semver from "./internal/semver.js";
import { pinnedKeys, type PinnedKey } from "./internal/sigstore/keyed.js";
import { cloneExpected, REGISTER_SIZE, type Expected } from "./measurement.js";
import { verificationOf, type ArtifactVerification, type ConfigVerification, type Verification } from "./verification.js";

/**
 * An exact config the caller trusts, as its bytes, optionally with its name.
 * The digest and the runtime pin are taken from the bytes, so the fields of
 * the reference form are excluded: an object carrying both forms is refused
 * at compile time, not just at runtime.
 */
export interface EmbeddedConfigBytes {
  /** The /org/project/revision name; absent or "" leaves the name unpinned. */
  readonly name?: string;
  /** The config bytes. */
  readonly bytes: Uint8Array;
  readonly digest?: never;
  readonly runtime?: never;
}

/**
 * An exact config the caller trusts without holding its bytes: its digest
 * and the runtime release it pins, optionally with its name. The document's
 * config endorsement is not consulted; the quote must still bind the digest.
 * The bytes form's field is excluded, so an object carrying both forms is
 * refused at compile time.
 */
export interface EmbeddedConfigReference {
  /** The /org/project/revision name; absent or "" leaves the name unpinned. */
  readonly name?: string;
  /** Lowercase hex SHA-256 of the config bytes. */
  readonly digest: string;
  /** The runtime release the config pins (its `cvm-version`). */
  readonly runtime: RuntimeReference;
  readonly bytes?: never;
}

/** Caller-trusted reference values that replace endorsement checks for the components supplied. */
export interface EmbeddedReferences {
  /** The exact config: its bytes, or its digest and runtime pin when the bytes themselves are not disclosed. */
  readonly config?: EmbeddedConfigBytes | EmbeddedConfigReference;
  /** The exact runtime manifest the config pins. */
  readonly runtime?: Uint8Array;
  /** A platform-endorsements/v2 policy artifact. */
  readonly platform?: Uint8Array;
}

/**
 * Names the workload a caller trusts and the namespace that vouches for it.
 * The two namespaces are unrelated: the same name can belong to different
 * owners in each, so a pin in one is never satisfied by the other.
 *
 * Setting both accepts a document that satisfies either. A pin with neither
 * accepts any config authorized by the verifier's registry trust, embedded
 * config or config authorizer. An absent part and "" are the same.
 */
export interface Pin {
  /** A GitHub repository, `owner/name[@tag][@sha256:digest]`. Only a document carrying that repository's signed release satisfies it. */
  readonly repo?: string;
  /** A config registry project, `org/project[@revision][@sha256:digest]`. Only a document carrying a registry approval of that project satisfies it. */
  readonly project?: string;
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
   * The exact registry IDs a config approval may be accepted under, replacing
   * public-only trust: an approval certified for any other registry rejects.
   * To accept the public registry alongside others, list it:
   * `[PUBLIC_REGISTRY_ID, ...mine]`. Needs registry trust, so it conflicts
   * with config signing keys, an embedded config and a config authorizer.
   * Must be non-empty, canonical and without repeats.
   */
  readonly configRegistryIDs?: readonly string[];
  /**
   * Caller-trusted reference values, each replacing the document's
   * endorsement of that component: `config` pins the exact config, as
   * `{ bytes, name? }` (the digest and runtime pin are taken from the bytes)
   * or `{ digest, runtime, name? }`; `runtime` pins the exact runtime
   * manifest, which on its own must be the release the document's config
   * endorsement names, and with an embedded config must be the one that
   * config pins; `platform` pins a platform-endorsements/v2 policy
   * artifact. At least one must be present.
   * An embedded config selects its own trust source, so it conflicts with
   * `configSigningKeys`, `configAuthorizer` and `configRegistryIDs`; with
   * both `runtime` and `platform` embedded, `freshnessSigningKeys` has no
   * endorsed artifact to verify and is refused.
   */
  readonly embeddedReferences?: EmbeddedReferences;
}

/**
 * @internal Trust roots that replace the embedded production anchors, for
 * verifying test vectors signed under their own roots. {@link Verifier.create}
 * injects none; only {@link buildVerifier} takes them, and the package entry
 * exports neither.
 */
export interface InjectedRoots extends quote.VendorRoots {
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

/** The parts a built verifier is made of. */
interface Parts {
  readonly policy: Policy;
  readonly prov: ProvenanceClient;
  readonly configVerifier: ConfigVerifier;
  readonly freshnessVerifier: FreshnessVerifier;
  readonly roots: quote.VendorRoots;
}

/** Only this module holds the token the constructor requires, so untyped code that calls it is refused. */
const BUILT_HERE: unique symbol = Symbol("Verifier");

/** Calls the private constructor; the class assigns it, as the only place the constructor can be called. */
let construct: (parts: Parts) => Verifier;

/**
 * Appraises v3 attestation documents against a fixed policy. Immutable once
 * built, and built only by {@link Verifier.create}: the constructor is
 * private, so type-checked code cannot call it, and a call from untyped
 * code is refused at runtime.
 */
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

  private constructor(token: typeof BUILT_HERE, parts: Parts) {
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

  static {
    construct = (parts) => new Verifier(BUILT_HERE, parts);
  }

  /**
   * Builds a verifier. Defaults use the embedded production trust roots,
   * Tinfoil's public signing keys, and a seven-day freshness bound.
   * Throws UsageError for invalid options.
   */
  static async create(options: VerifierOptions = {}): Promise<Verifier> {
    return buildVerifier(options, {});
  }

  /**
   * Throws UsageError when `pin` cannot be verified under this verifier's
   * policy, whatever the document: a malformed `repo` or `project`; a `repo`
   * set alone when the verifier verifies registry collateral only, through
   * an embedded reference, explicit signing keys, registry IDs or a config
   * authorizer; a `project` when a config authorizer is set; or a `project`
   * that an embedded config's name or digest doesn't match. No document or
   * network I/O. Verification can still refuse a pin that passes: registry
   * collateral also requires the project and revision to be valid config
   * identity components, and that check waits for the document.
   */
  checkPinVerifiability(pin: Pin): void {
    const { repo, project } = pinOf(pin);
    if (repo !== "") {
      usage(() => parseReference(repo));
      if (project === "" && this.#requiresConfigCollateral()) {
        throw new UsageError("configured trust verifies registry collateral only, which a GitHub repository pin cannot match");
      }
    }
    this.#referencePins(project);
  }

  /**
   * Appraises a nonce-bound v3 document against `pin` at the current time.
   * The document's collateral decides which part of `pin` applies, and a
   * document whose collateral `pin` does not cover is rejected.
   */
  async verifyV3(docBytes: Uint8Array, nonce: Uint8Array, pin: Pin): Promise<Verification> {
    return this.verifyV3At(docBytes, nonce, pin, new Date());
  }

  /**
   * Like {@link verifyV3}, but `verificationTime` replaces the clock in every
   * time-bound check (freshness, vendor certificate and CRL validity).
   */
  async verifyV3At(docBytes: Uint8Array, nonce: Uint8Array, pin: Pin, verificationTime: Date): Promise<Verification> {
    if (!(verificationTime instanceof Date) || !Number.isFinite(verificationTime.getTime())) {
      throw new UsageError("verification time must be a valid date");
    }
    const { repo, project } = pinOf(pin);
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
      // A malformed pin is the caller's mistake whichever collateral the document carries.
      if (repo !== "") usage(() => parseReference(repo));
      this.#referencePins(project);
      switch (doc.collateralFormat()) {
        case FORMAT_V3:
          if (project === "" && repo !== "") {
            throw new Error("document carries config registry collateral, but only a GitHub repository is pinned");
          }
          return this.#configReferences(doc, project, now);
        case FORMAT_V2:
          if (repo === "" && !this.#requiresConfigCollateral()) {
            throw new Error("document carries GitHub repository collateral, but no GitHub repository is pinned");
          }
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

    return verificationOf({
      configRepo: refs.artifact.repo,
      codeDigest: refs.artifact.digest,
      codeTag: refs.artifact.tag,
      codeMeasurement: assembled.codeMeasurement,
      enclaveMeasurement: authenticated.measurement,
      cryptoMaterial: doc.cryptoMaterialItems(),
      config: refs.config,
      runtime: refs.config === undefined ? undefined : refs.artifact,
      platform: refs.platform,
      freshnessExpiresAt: new Date(Math.min(refs.freshnessExpiresAt?.getTime() ?? Infinity, authenticated.expiresAt.getTime())),
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
      throw caused(`verifying platform endorsements: ${message(err)}`, err);
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
      throw caused(`verifying ${what} freshness: ${message(err)}`, err);
    }
  }

  // ---------------------------------------------------------------- config-pinned runtimes (collateral v3)

  /**
   * The config pins the project reference `ref` imposes, as a config policy without a clock. The
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

  async #configReferences(doc: Document, project: string, now: Date): Promise<References> {
    const pins = this.#referencePins(project);
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
        throw new VerificationError(`authorizing config: ${message(err)}`, { layer: "provenance", cause: err });
      }
      const digest = toHex(await sha256(config));
      return { expected: configRuntime(config), config: { source: "policy", name: "", digest, reference: "", signingKeyHint: "", registryID: "" } };
    }
    if (material.bundle === undefined) throw new Error("unsigned config requires a config authorizer");
    // The document carries the bundle as its source text; parsing it again
    // strictly reproduces the tree the approval verifier works on.
    const bundle = strictParse(utf8(material.bundle));
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
          ? await this.#configVerifier.verifyCertified(material.config, bundle, material.issuer, policy)
          : await this.#configVerifier.verify(material.config, bundle, policy);
    } catch (err) {
      throw caused(`verifying config approval: ${message(err)}`, err);
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
      throw caused(`verifying ${what} freshness: ${message(err)}`, err);
    }
  }
}

/** Validates every option, resolves the trust material and assembles the verifier. */
async function assemble(options: VerifierOptions, roots: InjectedRoots): Promise<Verifier> {
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
  const configRegistryIDs = options.configRegistryIDs === undefined ? undefined : usage(() => registryIDsOf(options.configRegistryIDs!));
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
  return construct({ policy, prov, configVerifier, freshnessVerifier, roots: { amd: roots.amd, intel: roots.intel } });
}

/**
 * @internal Validates the options and assembles the verifier under `roots`,
 * where an absent root selects the embedded production anchor; any failure
 * is a UsageError. {@link Verifier.create} is this with no roots injected.
 * Not exported from the package entry.
 */
export async function buildVerifier(options: VerifierOptions, roots: InjectedRoots): Promise<Verifier> {
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
 * The parts of `pin` as strings, "" for one that is unset. A pin that is not
 * an object of strings is refused, so that a bare reference string from
 * untyped code is not read as an empty pin.
 */
function pinOf(pin: Pin): { repo: string; project: string } {
  if (typeof pin !== "object" || pin === null) throw new UsageError("pin must be an object with a repo, a project, or both");
  const { repo = "", project = "" } = pin;
  if (typeof repo !== "string" || typeof project !== "string") throw new UsageError("pin repo and project must be strings");
  return { repo, project };
}

/** Validates and copies the caller's registry ID list: the exact accepted set. */
function registryIDsOf(registryIDs: readonly string[]): readonly string[] {
  if (!Array.isArray(registryIDs) || registryIDs.some((s) => typeof s !== "string")) throw new Error("config registry IDs must be a list of strings");
  validateRegistryIDs(registryIDs);
  return [...registryIDs];
}

/**
 * Runs one pipeline step; an error that is not already classified is
 * attributed to `layer`. That includes the verifier's own failures inside
 * the step, so the pipeline fails closed: a document is rejected rather
 * than accepted by an error, and the underlying error stays as `cause`.
 */
async function at<T>(layer: Layer, step: () => Promise<T>): Promise<T> {
  try {
    return await step();
  } catch (err) {
    if (err instanceof VerifyError) throw err;
    throw new VerificationError(message(err), { layer, cause: err });
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
  if (refs.config === undefined && refs.runtime === undefined && refs.platform === undefined) {
    throw new UsageError("embedded references must contain at least one component");
  }
  const configReference = refs.config === undefined ? undefined : await configReferenceOf(refs.config);
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

/**
 * The config reference an embedded config settles to: derived from its
 * bytes, or a copy of the caller's digest and runtime pin. The type admits
 * one form or the other; an object from untyped code that has both or
 * neither is refused.
 */
async function configReferenceOf(config: EmbeddedConfigBytes | EmbeddedConfigReference): Promise<ConfigReference> {
  if (typeof config !== "object" || config === null) throw new UsageError("embedded config must be an object");
  const hasBytes = (config as Partial<EmbeddedConfigBytes>).bytes !== undefined;
  const hasDigest = (config as Partial<EmbeddedConfigReference>).digest !== undefined;
  if (hasBytes === hasDigest) throw new UsageError("embedded config is either its bytes or its digest and runtime pin, not both or neither");
  if (hasBytes) {
    const { name, bytes } = config as EmbeddedConfigBytes;
    if (!(bytes instanceof Uint8Array)) throw new UsageError("embedded config bytes must be a Uint8Array");
    // Copied once so the digest and the runtime pin come from the same bytes, whatever the caller does to its buffer meanwhile.
    const copy = bytes.slice();
    return { name: name ?? "", digest: toHex(await sha256(copy)), runtime: usage(() => configRuntime(copy)) };
  }
  return usage(() => referenceCopyOf(config as EmbeddedConfigReference));
}

/** A copy of the caller's config reference with every field a string; validation follows. */
function referenceCopyOf(ref: EmbeddedConfigReference): ConfigReference {
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

/** A plain error with `message` whose `cause` is `err`, for a step that rewords a failure and must not lose it. */
function caused(message: string, err: unknown): Error {
  const wrapped = new Error(message);
  (wrapped as { cause?: unknown }).cause = err;
  return wrapped;
}
