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
import { UsageError, VerificationError, verificationMessage, VerifyError, type Layer } from "./errors.js";
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
import { measuredKeys, ReportBuilder, type VerificationReport } from "./report.js";
import { verifiedFactsOf, type ArtifactVerification, type ConfigVerification, type VerificationMetadata, type VerifiedFacts } from "./verification.js";

/**
 * Who vouches for the config that an enclave runs: one of {@link Registries},
 * {@link ConfigSigningKeys}, {@link ConfigAuthorizer}, {@link EmbeddedConfig}
 * or {@link EmbeddedConfigReference}, told apart by `kind`. Undefined selects
 * Tinfoil's public registry. Every choice other than undefined requires
 * attestation-collaterals/v3.
 */
export type ConfigTrust = Registries | ConfigSigningKeys | ConfigAuthorizer | EmbeddedConfig | EmbeddedConfigReference;

/**
 * Trusts configs that exactly these registries endorse, under Tinfoil's
 * registry root, in place of the public registry alone. To keep the public
 * registry, list {@link PUBLIC_REGISTRY_ID}: `[PUBLIC_REGISTRY_ID, ...mine]`.
 * `ids` must be non-empty, canonical and without repeats.
 */
export interface Registries {
  readonly kind: "registries";
  readonly ids: readonly string[];
}

/**
 * Trusts configs whose endorsements these PEM-encoded P-256 public keys
 * sign, in place of Tinfoil's registry root. This trust path uses no
 * registry IDs and doesn't authorize artifact freshness. `keys` must not be
 * empty.
 */
export interface ConfigSigningKeys {
  readonly kind: "configSigningKeys";
  readonly keys: readonly string[];
}

/**
 * Replaces config endorsement verification with the caller's policy.
 * `authorize` receives detached, untrusted material and must throw for
 * config bytes that it doesn't authorize; a throw rejects the document at
 * the provenance layer. It may run concurrently. Runtime, platform and
 * hardware checks still apply. Approval authenticates no registry name or
 * timestamp, so a `project` pin is a {@link UsageError}.
 */
export interface ConfigAuthorizer {
  readonly kind: "configAuthorizer";
  readonly authorize: (endorsement: ConfigEndorsement) => void | Promise<void>;
}

/**
 * Trusts the exact config bytes that the caller supplies, in place of a
 * registry endorsement; the digest and the runtime that the config pins are
 * taken from the bytes. `name`, an /org/project/revision identity, optionally
 * names them, and a `project` pin must then match it. The bytes must come
 * from trusted client configuration.
 */
export interface EmbeddedConfig {
  readonly kind: "embeddedConfig";
  /** The /org/project/revision name; absent or "" leaves the name unpinned. */
  readonly name?: string;
  readonly bytes: Uint8Array;
}

/**
 * Trusts an exact config that the caller identifies without disclosing its
 * bytes: the hex SHA-256 `digest` of its bytes and the `runtime` release that
 * it pins. The quote must still bind the digest. Otherwise it is
 * {@link EmbeddedConfig}.
 */
export interface EmbeddedConfigReference {
  readonly kind: "embeddedConfigReference";
  /** The /org/project/revision name; absent or "" leaves the name unpinned. */
  readonly name?: string;
  /** Lowercase hex SHA-256 of the config bytes. */
  readonly digest: string;
  /** The runtime release that the config pins (its `cvm-version`). */
  readonly runtime: RuntimeReference;
}

/**
 * How the runtime and platform artifacts are trusted: {@link EndorsedArtifacts}
 * or {@link EmbeddedArtifacts}, told apart by `kind`. Undefined selects
 * `{ kind: "endorsedArtifacts" }`.
 */
export type ArtifactTrust = EndorsedArtifacts | EmbeddedArtifacts;

/**
 * Trusts runtime and platform artifacts that the document's endorsements
 * authenticate and whose freshness approvals `freshnessKeys` sign:
 * PEM-encoded P-256 public keys. Undefined `freshnessKeys` selects Tinfoil's
 * public keys, which approve artifacts only and authorize no config. An
 * explicit key set requires attestation-collaterals/v3, and an empty one is
 * a {@link UsageError}.
 */
export interface EndorsedArtifacts {
  readonly kind: "endorsedArtifacts";
  readonly freshnessKeys?: readonly string[];
}

/**
 * Trusts caller-supplied runtime and platform artifacts in place of their
 * endorsements, and requires attestation-collaterals/v3. `runtime` is the
 * exact runtime manifest that the config pins, and `platform` is a
 * platform-endorsements/v2 policy artifact. No endorsement is consulted for
 * a supplied artifact, even if the document carries one. An artifact that
 * is left out is still endorsed, with its freshness approval signed by
 * `freshnessKeys`, as {@link EndorsedArtifacts} describes. At least one
 * artifact must be supplied, and `freshnessKeys` must be left out when both
 * are, since nothing is left for them to verify. Hardware authentication,
 * component bindings and pins remain mandatory. These values must come from
 * trusted client configuration.
 */
export interface EmbeddedArtifacts {
  readonly kind: "embeddedArtifacts";
  readonly runtime?: Uint8Array;
  readonly platform?: Uint8Array;
  readonly freshnessKeys?: readonly string[];
}

/**
 * The checks that a verifier applies on top of its config trust, as plain
 * data. Every field is optional, and the empty policy keeps every default:
 * no register pins, the seven-day freshness bound, and runtime and platform
 * artifacts that Tinfoil's public keys endorse.
 */
export interface Policy {
  /**
   * Registers that the enclave must match in addition to the release's: each
   * set register fills one that the release leaves open, and must equal one
   * that the release fixes. Pins for one platform reject every enclave on the
   * other. It is copied, so later changes by the caller have no effect.
   */
  readonly pinnedRegisters?: Expected;
  /** How old an authenticated witness may be; 0 or undefined selects seven days, and a negative age is a {@link UsageError}. */
  readonly freshnessMaxAgeMs?: number;
  /** How the runtime and platform artifacts are trusted; undefined selects `{ kind: "endorsedArtifacts" }`. */
  readonly artifacts?: ArtifactTrust;
}

/**
 * Names the workload a caller trusts. `repo` and `project` are separate
 * namespaces with unrelated owners, so neither is satisfied by the other's
 * collateral. Setting both accepts either; with neither, any config the
 * verifier's trust authorizes is accepted, which is a UsageError under default
 * config trust. An absent part and "" are the same.
 */
export interface Pin {
  /** A GitHub repository, `owner/name[@tag][@sha256:digest]`. */
  readonly repo?: string;
  /** A config registry project, `org/project[@revision][@sha256:digest]`. */
  readonly project?: string;
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

/** The policy and config trust as the verifier holds them: validated and copied. */
interface Settings {
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
  readonly policy: Settings;
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
  readonly #policy: Settings;
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
    // The properties describe the policy the verifier enforces, so neither can be changed after it is built.
    Object.freeze(this);
  }

  static {
    construct = (parts) => new Verifier(BUILT_HERE, parts);
  }

  /**
   * Builds a verifier that trusts configs as `config` selects and applies
   * `policy`. Undefined `config` selects Tinfoil's public registry, and an
   * undefined or empty `policy` keeps every default: the embedded production
   * trust roots, Tinfoil's public artifact signing keys and a seven-day
   * freshness bound. Both are copied, so later changes by the caller have no
   * effect. Throws UsageError for an invalid field, an unknown `kind` among
   * them.
   */
  static async create(config?: ConfigTrust, policy?: Policy): Promise<Verifier> {
    return buildVerifier(config, policy, {});
  }

  /**
   * Throws UsageError, without a document or network I/O, for a pin that
   * verification rejects whatever the document: one that names nothing under
   * default config trust, a malformed reference, a
   * `repo` set alone when the verifier verifies registry collateral only, or
   * a `project` that its config authorizer or embedded config cannot match.
   */
  checkPinVerifiability(pin: Pin): void {
    const { repo, project } = pinOf(pin);
    this.#requirePin(repo, project);
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
   * The document's collateral decides which part of `pin` applies.
   *
   * A document that it accepts resolves to a {@link VerificationReport}
   * whose `verifiedFacts` hold what the document proved; the caller must
   * bind its traffic to the keys in them and enforce their
   * `freshnessExpiresAt`. A document that it rejects rejects with a
   * {@link VerificationError} whose `report` shows the step that failed and
   * what the steps before it established. A {@link UsageError} carries no
   * report, because it reports a mistake in the caller's code rather than a
   * rejected document.
   */
  async verifyV3(docBytes: Uint8Array, nonce: Uint8Array, pin: Pin): Promise<VerificationReport> {
    return this.verifyV3At(docBytes, nonce, pin, new Date());
  }

  /**
   * Like {@link verifyV3}, but `verificationTime` replaces the clock in every
   * time-bound check (freshness, vendor certificate and CRL validity), and
   * the report's `metadata.verifiedAt` reports it.
   */
  async verifyV3At(docBytes: Uint8Array, nonce: Uint8Array, pin: Pin, verificationTime: Date): Promise<VerificationReport> {
    if (!(verificationTime instanceof Date) || !Number.isFinite(verificationTime.getTime())) {
      throw new UsageError("verification time must be a valid date");
    }
    const { repo, project } = pinOf(pin);
    // A malformed pin is a usage error for any document.
    this.#requirePin(repo, project);
    if (repo !== "") usage(() => parseReference(repo));
    this.#referencePins(project);
    const now = new Date(verificationTime.getTime());
    const metadata: VerificationMetadata = { verifier: { name: VERIFIER_NAME, version: VERIFIER_VERSION }, verifiedAt: now };
    const steps = new ReportBuilder();
    let verified: VerifiedFacts;
    try {
      verified = await this.#verify(docBytes, nonce, repo, project, now, steps);
    } catch (err) {
      // A usage error passes through without a report; a step's rejection
      // becomes a VerificationError at its layer that carries the report.
      if (!(err instanceof StepFailure)) throw err;
      const report = steps.failed(err.layer, verificationMessage(err.layer, err.message), metadata);
      throw new VerificationError(err.message, { layer: err.layer, report, cause: err.cause });
    }
    return steps.passedAll(verified, metadata);
  }

  /**
   * The verification itself: it records in `steps` each step that passes,
   * and the facts that the step establishes, from the values that the step
   * already computes. A rejection is a {@link StepFailure}.
   */
  async #verify(docBytes: Uint8Array, nonce: Uint8Array, repo: string, project: string, now: Date, steps: ReportBuilder): Promise<VerifiedFacts> {
    const doc = await at("envelope", async () => {
      try {
        return await parseDocument(docBytes, nonce);
      } catch (err) {
        if (err instanceof InvalidInputError) throw new UsageError(err.message, { cause: err });
        throw err;
      }
    });
    steps.passed("envelope");
    steps.measured = await measuredKeys(doc.cryptoMaterialItems());

    const refs = await at("provenance", async () => {
      switch (doc.collateralFormat()) {
        case FORMAT_V3:
          if (project === "" && repo !== "") {
            throw new Error("document carries config registry collateral, but only a GitHub repository is pinned");
          }
          return this.#configReferences(doc, project, now);
        case FORMAT_V2:
          if (repo === "" && project !== "" && !this.#requiresConfigCollateral()) {
            throw new Error("document carries GitHub repository collateral, but only a registry project is pinned");
          }
          return this.#codeReferences(doc, repo, now);
        default:
          throw new Error(`unsupported collateral format ${JSON.stringify(doc.collateralFormat())}`);
      }
    });

    if (embedded(refs)) {
      steps.set("provenance", "skipped", "the verifier embeds every reference value, so there is no endorsement to authenticate");
    } else {
      steps.passed("provenance");
    }
    steps.expected = {
      configRepo: refs.artifact.repo,
      artifact: refs.artifact,
      ...(refs.config === undefined ? {} : { config: refs.config }),
      ...(refs.platform === undefined ? {} : { platform: refs.platform }),
    };
    const code = quote.codeMeasurement(refs.quote, doc.cpuEvidence().format);
    if (code !== undefined) steps.expected.codeMeasurement = code;

    const authenticated = await at("quote", () =>
      quote.authenticate(doc.cpuEvidence(), doc.cpuEndorsements(), now, { dangerousTestOnlyRoots: this.#roots }),
    );
    steps.passed("quote");
    steps.measured.cpu = { measurement: authenticated.measurement };

    const expected = steps.expected;
    const assembled = await at("policy", async () => {
      try {
        return await quote.assemble(doc, refs.quote, this.#policy.pinnedRegisters, authenticated);
      } catch (err) {
        // The registers were resolved before the failure, so the report shows them.
        if (!(err instanceof quote.ResolvedError)) throw err;
        expected.measurement = err.expected;
        throw err.cause;
      }
    });
    expected.measurement = assembled.expected;
    await at("policy", () => quote.validate(assembled));
    steps.passed("policy");

    return verifiedFactsOf({
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
    });
  }

  // ---------------------------------------------------------------- code releases (collateral v2)

  /** Refuses a pin that names nothing under default config trust, which would accept any config in the public registry. */
  #requirePin(repo: string, project: string): void {
    const p = this.#policy;
    if (repo !== "" || project !== "" || p.embedded.configReference !== undefined || p.configAuthorizer !== undefined || p.configKeysPinned || p.configRegistryIDs !== undefined) return;
    throw new UsageError("pin names nothing: set repo or project, or configure the verifier's config trust");
  }

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
        throw new StepFailure("provenance", `authorizing config: ${message(err)}`, err);
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

/** Validates the config trust and the policy, resolves the trust material and assembles the verifier. */
async function assemble(config: ConfigTrust | undefined, policy: Policy | undefined, roots: InjectedRoots): Promise<Verifier> {
  const prov = roots.sigstore ? await ProvenanceClient.fromJSON(roots.sigstore) : await ProvenanceClient.default();
  if (policy !== undefined && (typeof policy !== "object" || policy === null)) throw new UsageError("policy must be an object");
  const pinnedRegisters = policy?.pinnedRegisters === undefined ? undefined : validPins(policy.pinnedRegisters);
  const freshnessMaxAgeMs = freshnessBound(policy?.freshnessMaxAgeMs);
  // The artifacts come first, so that an embedded config can check an embedded runtime against itself.
  const artifacts = await artifactTrustOf(policy?.artifacts);
  const trust = await configTrustOf(config, artifacts.runtime);
  const publicKeys = await publicSigningKeys();
  // Without caller-pinned config keys, the public keys are the registry
  // roots as well: they issue the signing certificates of certified approvals.
  const registryKeys = roots.registryRoots === undefined ? publicKeys : await keysOf("registry roots", roots.registryRoots);
  const configVerifier = trust.configKeys === undefined ? new ConfigVerifier(prov.root, registryKeys, registryKeys) : new ConfigVerifier(prov.root, trust.configKeys);
  const freshnessVerifier = new FreshnessVerifier(prov.root, artifacts.freshnessKeys ?? publicKeys);
  const settings: Settings = {
    embedded: {
      ...(trust.configReference === undefined ? {} : { configReference: trust.configReference }),
      ...(artifacts.runtime === undefined ? {} : { runtime: artifacts.runtime }),
      ...(artifacts.platform === undefined ? {} : { platform: artifacts.platform }),
    },
    pinnedRegisters,
    freshnessMaxAgeMs,
    configAuthorizer: trust.configAuthorizer,
    configRegistryIDs: trust.configRegistryIDs,
    configKeysPinned: trust.configKeys !== undefined,
    freshnessKeysPinned: artifacts.freshnessKeys !== undefined,
  };
  return construct({ policy: settings, prov, configVerifier, freshnessVerifier, roots: { amd: roots.amd, intel: roots.intel } });
}

/**
 * @internal Validates the config trust and the policy and assembles the
 * verifier under `roots`, where an absent root selects the embedded
 * production anchor; any failure is a UsageError. {@link Verifier.create} is
 * this with no roots injected. Not exported from the package entry.
 */
export async function buildVerifier(config: ConfigTrust | undefined, policy: Policy | undefined, roots: InjectedRoots): Promise<Verifier> {
  try {
    return await assemble(config, policy, roots);
  } catch (err) {
    if (err instanceof UsageError) throw err;
    throw new UsageError(message(err), { cause: err });
  }
}

/** An {@link ArtifactTrust}, validated and copied. */
interface ArtifactSettings {
  readonly freshnessKeys?: PinnedKey[];
  readonly runtime?: Uint8Array;
  readonly platform?: Uint8Array;
}

/** Validates and copies `artifacts`; undefined selects the endorsed artifacts under Tinfoil's keys. */
async function artifactTrustOf(artifacts: ArtifactTrust | undefined): Promise<ArtifactSettings> {
  if (artifacts === undefined) return {};
  switch (kindOf(artifacts, "artifact trust")) {
    case "endorsedArtifacts": {
      const a = artifacts as EndorsedArtifacts;
      return a.freshnessKeys === undefined ? {} : { freshnessKeys: await keysOf("freshness signing keys", a.freshnessKeys) };
    }
    case "embeddedArtifacts": {
      const a = artifacts as EmbeddedArtifacts;
      const runtime = optionalBytes("embedded runtime", a.runtime);
      const platform = optionalBytes("embedded platform", a.platform);
      if (runtime === undefined && platform === undefined) throw new UsageError("embedded artifacts must contain a runtime or a platform");
      if (runtime !== undefined && platform !== undefined && a.freshnessKeys !== undefined) {
        throw new UsageError("freshness signing keys have no endorsed artifact to verify");
      }
      const freshnessKeys = a.freshnessKeys === undefined ? undefined : await keysOf("freshness signing keys", a.freshnessKeys);
      if (runtime !== undefined) decodeManifest(runtime);
      if (platform !== undefined && parseArtifact(platform).format !== ARTIFACT_FORMAT_V2) {
        throw new UsageError("embedded platform requires platform-endorsements/v2");
      }
      return {
        ...(freshnessKeys === undefined ? {} : { freshnessKeys }),
        ...(runtime === undefined ? {} : { runtime }),
        ...(platform === undefined ? {} : { platform }),
      };
    }
    default:
      throw new UsageError(`artifact trust must have kind "endorsedArtifacts" or "embeddedArtifacts", not ${describeKind(artifacts)}`);
  }
}

/** A {@link ConfigTrust}, validated and copied; every member is unset under the public registry. */
interface ConfigTrustSettings {
  readonly configRegistryIDs?: readonly string[];
  readonly configKeys?: PinnedKey[];
  readonly configAuthorizer?: (endorsement: ConfigEndorsement) => void | Promise<void>;
  readonly configReference?: ConfigReference;
}

/**
 * Validates and copies `config`; undefined selects the public registry. An
 * embedded config is checked against `embeddedRuntime`, the caller's own
 * runtime manifest when it embeds one: both come from the caller, so a
 * manifest that the config doesn't pin is rejected here rather than at
 * verification.
 */
async function configTrustOf(config: ConfigTrust | undefined, embeddedRuntime: Uint8Array | undefined): Promise<ConfigTrustSettings> {
  if (config === undefined) return {};
  switch (kindOf(config, "config trust")) {
    case "registries":
      return { configRegistryIDs: usage(() => registryIDsOf((config as Registries).ids)) };
    case "configSigningKeys":
      return { configKeys: await keysOf("config signing keys", (config as ConfigSigningKeys).keys) };
    case "configAuthorizer": {
      const authorize = (config as ConfigAuthorizer).authorize;
      if (typeof authorize !== "function") throw new UsageError("config authorizer must be a function");
      return { configAuthorizer: authorize };
    }
    case "embeddedConfig":
    case "embeddedConfigReference": {
      const reference = await configReferenceOf(config as EmbeddedConfig | EmbeddedConfigReference);
      if (reference.name !== "") usage(() => parseConfigName(reference.name));
      usage(() => decodeLowerHex("config digest", reference.digest, 32));
      usage(() => validateRuntimeReference(reference.runtime));
      if (embeddedRuntime !== undefined) await parseManifest(embeddedRuntime, reference.runtime);
      return { configReference: reference };
    }
    default:
      throw new UsageError(
        `config trust must have kind "registries", "configSigningKeys", "configAuthorizer", "embeddedConfig" or "embeddedConfigReference", not ${describeKind(config)}`,
      );
  }
}

/** The `kind` of a sum-type value that untyped code may have passed as anything; a non-object is a UsageError. */
function kindOf(value: unknown, what: string): unknown {
  if (typeof value !== "object" || value === null) throw new UsageError(`${what} must be an object with a kind`);
  return (value as { kind?: unknown }).kind;
}

/** How an unknown `kind` is named in an error. */
function describeKind(value: unknown): string {
  const kind = (value as { kind?: unknown }).kind;
  if (kind === undefined) return "a value without one";
  if (typeof kind === "string") return JSON.stringify(kind);
  if (typeof kind === "number" || typeof kind === "boolean" || typeof kind === "bigint" || kind === null) return String(kind);
  return `a ${typeof kind}`;
}

/** A copy of caller-supplied bytes, or undefined when they are absent; anything but a Uint8Array is a UsageError. */
function optionalBytes(what: string, bytes: unknown): Uint8Array | undefined {
  if (bytes === undefined) return undefined;
  if (!(bytes instanceof Uint8Array)) throw new UsageError(`${what} must be a Uint8Array`);
  return bytes.slice();
}

interface ConfigPins {
  readonly identity: string;
  readonly revision: string;
  readonly digest: string;
  readonly registryIDs?: readonly string[];
}

/** The parts of `pin`, "" when unset. A bare string is refused, not read as an empty pin. */
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
 * A step's rejection of the document at `layer`, which `verifyV3At` reports
 * as a {@link VerificationError} with the same message and cause once the
 * report is complete.
 */
class StepFailure extends Error {
  readonly layer: Layer;
  declare readonly cause?: unknown;

  constructor(layer: Layer, message: string, cause: unknown) {
    super(message);
    this.layer = layer;
    (this as { cause?: unknown }).cause = cause;
  }
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
    if (err instanceof VerifyError || err instanceof StepFailure) throw err;
    throw new StepFailure(layer, message(err), err);
  }
}

/**
 * Whether the caller embedded every reference value in the verifier, so
 * that provenance authenticated nothing: the config, the runtime and the
 * platform.
 */
function embedded(refs: References): boolean {
  return refs.config?.source === "embedded" && refs.artifact.source === "embedded" && refs.platform?.source === "embedded";
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
  if (!Array.isArray(pems) || pems.some((pem) => typeof pem !== "string")) throw new UsageError(`${what} must be a list of PEM strings`);
  if (pems.length === 0) throw new UsageError(`${what} must not be empty`);
  try {
    return await pinnedKeys(pems);
  } catch (err) {
    throw new UsageError(`${what}: ${message(err)}`, { cause: err });
  }
}

/**
 * The config reference that an embedded config settles to: derived from its
 * bytes, or a copy of the caller's digest and runtime pin.
 */
async function configReferenceOf(config: EmbeddedConfig | EmbeddedConfigReference): Promise<ConfigReference> {
  if (config.kind === "embeddedConfig") {
    const { name, bytes } = config;
    if (!(bytes instanceof Uint8Array)) throw new UsageError("embedded config bytes must be a Uint8Array");
    if (name !== undefined && typeof name !== "string") throw new UsageError("embedded config name must be a string");
    // Copied once so the digest and the runtime pin come from the same bytes, whatever the caller does to its buffer meanwhile.
    const copy = bytes.slice();
    return { name: name ?? "", digest: toHex(await sha256(copy)), runtime: usage(() => configRuntime(copy)) };
  }
  return usage(() => referenceCopyOf(config));
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
