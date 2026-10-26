import { sha256 as sha256Sync } from "@noble/hashes/sha2.js";
import { UsageError, atLayer } from "./errors.js";
import { hex, unhex } from "./encoding.js";
import { parseDocument, KEY_TLS, KEY_HPKE } from "./document.js";
import {
  defaultSigstoreRoot,
  TrustInitializationError,
  type SigstoreRoot,
} from "./sigstore.js";
import { DEFAULT_MAX_AGE, PLATFORM_V2 } from "./references.js";
import {
  DEFAULT_SIGNING_KEY,
  configName,
  validateSigningKey,
} from "./approvals.js";
import { decodeRuntimeManifest, runtimePin } from "./runtime.js";
import { parsePlatformArtifact } from "./policy/index.js";
import { authenticateQuote, validatePolicy } from "./quote/index.js";
import { verifyReferences, type ProvenanceOptions } from "./provenance.js";
import type {
  ArtifactVerification,
  ConfigVerification,
  CryptoMaterialItem,
  ExpectedMeasurement,
  Measurement,
  VerificationMetadata,
  VerifierOptions,
} from "./types.js";
import { VERIFIER_NAME, VERIFIER_VERSION } from "./version.js";
interface PrivateTrust {
  sigstoreRoot?: SigstoreRoot;
  amdRootPem?: string;
  intelRootPem?: string;
}
interface State {
  provenance: ProvenanceOptions;
  pins?: ExpectedMeasurement;
  trust: PrivateTrust;
}
const states = new WeakMap<Verifier, State>();
interface ResultData {
  configRepo: string;
  codeDigest: string;
  codeTag: string;
  codeMeasurement: ExpectedMeasurement;
  enclaveMeasurement: Measurement;
  cryptoMaterial: CryptoMaterialItem[];
  freshnessExpiresAt?: Date;
  metadata: VerificationMetadata;
  config?: ConfigVerification;
  runtime?: ArtifactVerification;
  platform?: ArtifactVerification;
}
const resultData = new WeakMap<Verification, ResultData>(),
  resultToken = Symbol("verified");
/** Only successful verification constructs this immutable value. Every aggregate accessor detaches its data. */
export class Verification {
  private constructor(token: symbol, data: ResultData) {
    if (token !== resultToken)
      throw new UsageError(
        "Verification results can only be created by a verifier",
      );
    resultData.set(this, structuredClone(data));
    Object.freeze(this);
  }
  get configRepo(): string {
    return data(this).configRepo;
  }
  get codeDigest(): string {
    return data(this).codeDigest;
  }
  get codeTag(): string {
    return data(this).codeTag;
  }
  get codeMeasurement(): ExpectedMeasurement {
    return Object.freeze({ ...data(this).codeMeasurement });
  }
  get enclaveMeasurement(): Measurement {
    return Object.freeze({ ...data(this).enclaveMeasurement });
  }
  get cryptoMaterial(): readonly CryptoMaterialItem[] {
    return Object.freeze(
      data(this).cryptoMaterial.map((x) => Object.freeze({ ...x })),
    );
  }
  get freshnessExpiresAt(): Date | undefined {
    const d = data(this).freshnessExpiresAt;
    return d && new Date(d);
  }
  get metadata(): VerificationMetadata {
    return structuredClone(data(this).metadata);
  }
  get config(): ConfigVerification | undefined {
    return structuredClone(data(this).config);
  }
  get runtime(): ArtifactVerification | undefined {
    return structuredClone(data(this).runtime);
  }
  get platform(): ArtifactVerification | undefined {
    return structuredClone(data(this).platform);
  }
  cryptoMaterialData(id: string, format: string): string | undefined {
    return data(this).cryptoMaterial.find(
      (x) => x.id === id && x.format === format,
    )?.data;
  }
  tlsPublicKeyFingerprint(): string | undefined {
    return this.cryptoMaterialData("tls", KEY_TLS);
  }
  hpkePublicKey(): string | undefined {
    return this.cryptoMaterialData("hpke", KEY_HPKE);
  }
}
function data(v: Verification): ResultData {
  const value = resultData.get(v);
  if (!value) throw new UsageError("Invalid Verification receiver");
  return value;
}
function createResult(value: ResultData): Verification {
  return Reflect.construct(Verification, [resultToken, value]) as Verification;
}
function copyKeys(keys: readonly Uint8Array[] | undefined): Uint8Array[] {
  if (keys === undefined) return [new Uint8Array(DEFAULT_SIGNING_KEY)];
  if (!Array.isArray(keys) || !keys.length)
    throw new Error("Signing key set must not be empty");
  const copied = keys.map((k) => {
    validateSigningKey(k);
    return new Uint8Array(k);
  });
  if (new Set(copied.map(hex)).size !== copied.length)
    throw new Error("Duplicate signing key");
  return copied;
}
function buildState(
  options: VerifierOptions = {},
  trust: PrivateTrust = {},
): State {
  if (!options || typeof options !== "object" || Array.isArray(options))
    throw new Error("Verifier options must be an object");
  const allowed = [
    "freshnessMaxAgeMs",
    "pinnedRegisters",
    "configSigningKeys",
    "freshnessSigningKeys",
    "embeddedReferences",
    "configAuthorizer",
  ];
  for (const k of Object.keys(options))
    if (!allowed.includes(k)) throw new Error(`Unknown verifier option ${k}`);
  const maxAge = options.freshnessMaxAgeMs ?? DEFAULT_MAX_AGE;
  if (!Number.isSafeInteger(maxAge) || maxAge < 0)
    throw new Error("Freshness maximum age must be a nonnegative integer");
  let pins = options.pinnedRegisters && { ...options.pinnedRegisters };
  if (pins) {
    const names =
      pins.type === "sev-snp"
        ? ["type", "launch"]
        : pins.type === "tdx"
          ? ["type", "mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"]
          : [];
    if (!names.length) throw new Error("Unsupported pin platform");
    for (const [k, v] of Object.entries(pins)) {
      if (!names.includes(k)) throw new Error("Unknown measurement register");
      if (k !== "type" && v !== undefined)
        (pins as unknown as Record<string, string>)[k] = hex(
          unhex(v, 48, false),
        );
    }
    Object.freeze(pins);
  }
  const embedded = structuredClone(options.embeddedReferences ?? {});
  if (
    options.embeddedReferences &&
    !embedded.config &&
    !embedded.runtime &&
    !embedded.platform
  )
    throw new Error("Embedded references must contain a component");
  if (embedded.config) {
    if (options.configSigningKeys || options.configAuthorizer)
      throw new Error(
        "Embedded config conflicts with signing keys or authorizer",
      );
    if (embedded.config.name) configName(embedded.config.name);
    const pin = runtimePin(embedded.config.bytes);
    if (embedded.runtime) {
      const m = decodeRuntimeManifest(embedded.runtime);
      if (
        m.version !== pin.tag ||
        hex(sha256Sync(embedded.runtime)) !== pin.digest
      )
        throw new Error("Embedded runtime does not match config pin");
    }
  }
  if (embedded.runtime) decodeRuntimeManifest(embedded.runtime);
  if (embedded.platform) parsePlatformArtifact(embedded.platform, PLATFORM_V2);
  if (
    options.configAuthorizer !== undefined &&
    (typeof options.configAuthorizer !== "function" ||
      options.configSigningKeys)
  )
    throw new Error("Invalid config authorizer or conflicting signing keys");
  if (embedded.runtime && embedded.platform && options.freshnessSigningKeys)
    throw new Error("Freshness signing keys have no endorsed artifact");
  return {
    provenance: {
      root: structuredClone(trust.sigstoreRoot ?? defaultSigstoreRoot()),
      maxAge,
      embedded,
      configKeys: copyKeys(options.configSigningKeys),
      freshnessKeys: copyKeys(options.freshnessSigningKeys),
      authorizer: options.configAuthorizer,
      requiresConfig: !!(
        options.embeddedReferences ||
        options.configSigningKeys ||
        options.freshnessSigningKeys ||
        options.configAuthorizer
      ),
    },
    pins,
    trust: { amdRootPem: trust.amdRootPem, intelRootPem: trust.intelRootPem },
  };
}
/** Immutable, offline verifier. Live verification samples one clock for every stage. */
export class Verifier {
  constructor(options: VerifierOptions = {}) {
    try {
      states.set(this, buildState(options));
    } catch (cause) {
      if (cause instanceof TrustInitializationError) throw cause;
      throw new UsageError(
        cause instanceof Error ? cause.message : "Invalid verifier options",
        { cause },
      );
    }
    Object.freeze(this);
  }
  get freshnessMaxAgeMs(): number {
    return state(this).provenance.maxAge;
  }
  get pinnedRegisters(): ExpectedMeasurement | undefined {
    const pins = state(this).pins;
    return pins && Object.freeze({ ...pins });
  }
  verify(
    bytes: Uint8Array,
    nonce: Uint8Array,
    identity: string,
  ): Promise<Verification> {
    return this.verifyDocumentV3(bytes, nonce, identity);
  }
  verifyDocumentV3(
    bytes: Uint8Array,
    nonce: Uint8Array,
    identity: string,
  ): Promise<Verification> {
    return this.verifyDocumentV3At(bytes, nonce, identity, new Date());
  }
  async verifyDocumentV3At(
    bytes: Uint8Array,
    nonce: Uint8Array,
    identity: string,
    verificationTime: Date,
  ): Promise<Verification> {
    const config = state(this);
    if (
      !(verificationTime instanceof Date) ||
      !Number.isFinite(verificationTime.getTime()) ||
      verificationTime.getTime() === -62135596800000
    )
      throw new UsageError("Verification time must be a valid nonzero Date");
    if (typeof identity !== "string")
      throw new UsageError("Trusted identity must be a string");
    const now = new Date(verificationTime);
    const doc = await atLayer("envelope", () =>
      parseDocument(
        bytes instanceof Uint8Array ? new Uint8Array(bytes) : bytes,
        nonce instanceof Uint8Array ? new Uint8Array(nonce) : nonce,
      ),
    );
    const refs = await atLayer("provenance", () =>
      verifyReferences(doc, identity, now, config.provenance),
    );
    const quote = await atLayer("quote", () =>
      authenticateQuote(doc.evidence, doc.collateral.cpu, now, config.trust),
    );
    const policy = await atLayer("policy", () =>
      validatePolicy(quote, refs.quote, doc.expectedReportData, config.pins),
    );
    return createResult({
      configRepo: refs.artifact.repo,
      codeDigest: refs.artifact.digest,
      codeTag: refs.artifact.tag,
      codeMeasurement: policy.codeMeasurement,
      enclaveMeasurement: quote.measurement,
      cryptoMaterial: doc.cryptoMaterial,
      freshnessExpiresAt: refs.expiresAt,
      metadata: {
        verifier: { name: VERIFIER_NAME, version: VERIFIER_VERSION },
        verifiedAt: now,
      },
      config: refs.config,
      runtime: refs.config ? refs.artifact : undefined,
      platform: refs.platform,
    });
  }
}
function state(v: Verifier): State {
  const s = states.get(v);
  if (!s) throw new UsageError("Invalid Verifier receiver");
  return s;
}
export function verifyDocumentV3(
  bytes: Uint8Array,
  nonce: Uint8Array,
  identity: string,
): Promise<Verification> {
  return new Verifier().verifyDocumentV3(bytes, nonce, identity);
}
export function verifyDocumentV3At(
  bytes: Uint8Array,
  nonce: Uint8Array,
  identity: string,
  time: Date,
): Promise<Verification> {
  return new Verifier().verifyDocumentV3At(bytes, nonce, identity, time);
}
/** @internal Private adapter composition: excluded from the published entry point and bundle. */
export function createVerifierForConformance(
  options: VerifierOptions = {},
  trust: PrivateTrust = {},
): Verifier {
  const v = new Verifier(options);
  states.set(v, buildState(options, trust));
  return v;
}
/** @internal Private adapter composition for isolated provenance; the same stage as full verification. */
export function provenanceOptionsForConformance(
  options: VerifierOptions = {},
  trust: PrivateTrust = {},
): ProvenanceOptions {
  return buildState(options, trust).provenance;
}
