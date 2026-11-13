/**
 * Approvals of configs and artifact freshness: each is a bundle over an
 * in-toto statement whose predicate carries an RFC 3161 timestamp of the
 * statement's canonical core; that timestamp, not the log, establishes when
 * the approval was made. A config approval is signed either with a pinned
 * key or, for a certified registry deployment, with a short-lived registry
 * certificate that assigns the registry ID and is itself timestamped and
 * rooted in a pinned registry key.
 */
import { RUNTIME_REPO, validateRuntimeReference, type RuntimeReference } from "../../document/collateral/runtime.js";
import { sha256, toHex } from "../bytes.js";
import { decodeBase64, decodeLowerHex } from "../canonical.js";
import { map, object, str, struct } from "../json/decode.js";
import { strictParse, type JsonObject, type JsonValue } from "../json/index.js";
import { configRuntime } from "../runtime/config.js";
import * as semver from "../semver.js";
import { parseBundle } from "../sigstore/bundle.js";
import { signedTimestamp, verifyCertifiedBundle } from "../sigstore/certified.js";
import { pinnedKeys, verifyKeyedBundle, type PinnedKey } from "../sigstore/keyed.js";
import { endorsementReference, MAX_STATEMENT_SIZE, MAX_TIMESTAMP_SIZE, timestampInput, verifyTimestamp } from "../sigstore/timestamp.js";
import type { TrustedRoot } from "../sigstore/trusted-root.js";
import { PUBLIC_SIGNING_KEY_PEM } from "../../trust/signing-keys.js";
import { SHA256_DIGEST_RE } from "./reference.js";
import { CERTIFICATE_CLOCK_SKEW_MS, verifySigningCertificate } from "./registry-certificate.js";
import { checkTime, newTimePolicy, type TimePolicy } from "./time.js";

export const IN_TOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1";
export const CONFIG_ENDORSEMENT_PREDICATE_TYPE = "https://tinfoil.sh/predicate/config-endorsement/v1";
export const CONFIG_ENDORSEMENT_PREDICATE_TYPE_V2 = "https://tinfoil.sh/predicate/config-endorsement/v2";
export const ARTIFACT_FRESHNESS_PREDICATE_TYPE = "https://tinfoil.sh/predicate/artifact-freshness/v1";
export const MAX_CONFIG_SIZE = 1 << 20;

export const KIND_PLATFORM = "platform";
export const KIND_RUNTIME = "runtime";
export type ArtifactKind = typeof KIND_PLATFORM | typeof KIND_RUNTIME;
export const PLATFORM_ARTIFACT_NAME = "platform-endorsements.json";
export const PLATFORM_TAG_PREFIX = "platform-";
const RUNTIME_NAME_PREFIX = "tinfoil-inference-";
const RUNTIME_NAME_SUFFIX = "-manifest.json";

/** Registry IDs are URIs under this prefix; the wire form keeps its historical path. */
export const REGISTRY_ID_PREFIX = "https://registry.tinfoil.sh/scopes/";
export const PUBLIC_REGISTRY_ID = REGISTRY_ID_PREFIX + "public";
const REGISTRY_ID_HEX_LEN = 32;

/** The domain prefixes of the timestamped canonical cores. */
const CONFIG_FRESHNESS_DOMAIN = "tinfoil-config-freshness/v1\0";
const CONFIG_FRESHNESS_DOMAIN_V2 = "tinfoil-config-freshness/v2\0";
const ARTIFACT_FRESHNESS_DOMAIN = "tinfoil-artifact-freshness/v1\0";

const MAX_SLUG_LENGTH = 63;
const MAX_REVISION_LENGTH = 128;
const SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const REVISION_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

const STATEMENT_MEMBERS = ["_type", "subject", "predicateType", "predicate"];
const SUBJECT_MEMBERS = ["name", "digest"];
const FRESHNESS_MEMBERS = ["rfc3161Timestamp"];
const CONFIG_PREDICATE_MEMBERS = ["scope", "runtime", "freshness"];
const RUNTIME_MEMBERS = ["repo", "tag", "digest"];
const ARTIFACT_PREDICATE_MEMBERS = ["kind", "repo", "tag", "freshness"];

/** Tinfoil's embedded public signing keys. */
export function publicSigningKeys(): Promise<PinnedKey[]> {
  return pinnedKeys([PUBLIC_SIGNING_KEY_PEM]);
}

// ---------------------------------------------------------------- names and registry IDs

/** The public registry ID, or a canonical private one: a 128-bit lowercase-hex identifier under the prefix. */
export function validateRegistryID(registryID: string): void {
  if (registryID === PUBLIC_REGISTRY_ID) return;
  if (registryID.startsWith(REGISTRY_ID_PREFIX)) {
    const id = registryID.slice(REGISTRY_ID_PREFIX.length);
    if (id.length === REGISTRY_ID_HEX_LEN && /^[0-9a-f]+$/.test(id)) return;
  }
  throw new Error("registry ID must be a canonical registry URI");
}

/** A canonical /org/project identity: exactly two slug components after a leading slash. */
export function validateConfigIdentity(identity: string): void {
  const parts = identity.split("/");
  if (parts.length !== 3 || parts[0] !== "") throw new Error(`invalid config identity ${JSON.stringify(identity)}`);
  for (const part of parts.slice(1)) validateIdentityComponent(part);
}

/** A lowercase slug of at most 63 characters. */
export function validateIdentityComponent(part: string): void {
  if (part.length > MAX_SLUG_LENGTH || !SLUG_RE.test(part)) throw new Error(`invalid config identity component ${JSON.stringify(part)}`);
}

/** A revision: alphanumeric start, then alphanumerics, '.', '_' or '-', at most 128 characters. */
export function validateRevision(revision: string): void {
  if (revision.length > MAX_REVISION_LENGTH || !REVISION_RE.test(revision)) throw new Error(`invalid config revision ${JSON.stringify(revision)}`);
}

/** Splits a versioned config name at its last '/' into a validated identity and revision. */
export function parseConfigName(name: string): { identity: string; revision: string } {
  if (name.includes("\0")) throw new Error("invalid config name");
  const last = name.lastIndexOf("/");
  if (last < 0) throw new Error("config name has no revision");
  const identity = name.slice(0, last);
  const revision = name.slice(last + 1);
  validateConfigIdentity(identity);
  validateRevision(revision);
  return { identity, revision };
}

// ---------------------------------------------------------------- statements

/** A subject with exactly one digest, sha256, lowercase. */
interface ApprovalSubject {
  readonly name: string;
  readonly digest: string;
}

/** The statement core shared by both approval profiles, plus the inner timestamp. */
interface ApprovalStatement {
  readonly type: string;
  readonly subject: ApprovalSubject;
  readonly predicateType: string;
  /** The DER TimeStampResp the predicate carries. */
  readonly timestamp: Uint8Array;
}

export interface ConfigStatement extends ApprovalStatement {
  /** The registry ID the statement names (its `scope` member); "" on a v1 statement. */
  readonly registryID: string;
  readonly runtime?: RuntimeReference;
}

export interface ArtifactFreshnessStatement extends ApprovalStatement {
  readonly artifact: FreshnessArtifact;
}

/** Bounds the payload and decodes the statement envelope with the given predicate members. */
function decodeStatement(payload: Uint8Array, predicateMembers: readonly string[]): { s: JsonObject; predicate: JsonObject } {
  if (payload.length === 0 || payload.length > MAX_STATEMENT_SIZE) throw new Error("statement size is outside allowed bounds");
  const s = object(strictParse(payload), "statement", STATEMENT_MEMBERS);
  return { s, predicate: struct(s, "predicate", predicateMembers) };
}

/** Exactly one subject with exactly one digest, under "sha256", lowercase hex. */
function singleSubject(s: JsonObject, what: string): ApprovalSubject {
  const list = s.get("subject");
  const subjects = list === undefined || list === null ? [] : list;
  if (!Array.isArray(subjects)) throw new Error("subject is not an array");
  if (subjects.length !== 1) throw new Error(`${what} requires exactly one subject`);
  const subject = object(subjects[0] as JsonValue, "subject[0]", SUBJECT_MEMBERS);
  const digests = map(subject, "digest", (v) => {
    if (v === null) return "";
    if (typeof v !== "string") throw new Error("subject digest is not a string");
    return v;
  });
  const digest = digests.get("sha256") ?? "";
  if (digests.size !== 1 || !SHA256_DIGEST_RE.test(digest)) throw new Error("subject requires one lowercase SHA-256 digest");
  return { name: str(subject, "name"), digest };
}

/** The predicate's `freshness.rfc3161Timestamp`: required, non-empty, bounded. */
function innerTimestamp(predicate: JsonObject, what: string): Uint8Array {
  const freshness = predicate.get("freshness");
  if (freshness === undefined || freshness === null) throw new Error(`${what} requires an inner timestamp`);
  const encoded = str(object(freshness, "freshness", FRESHNESS_MEMBERS), "rfc3161Timestamp");
  const timestamp = encoded === "" ? new Uint8Array() : decodeBase64("rfc3161Timestamp", encoded);
  if (timestamp.length === 0) throw new Error(`${what} requires an inner timestamp`);
  if (timestamp.length > MAX_TIMESTAMP_SIZE) throw new Error("inner timestamp exceeds size limit");
  return timestamp;
}

/**
 * Strict decode of a config endorsement statement: the in-toto v1 type, the
 * v1 or v2 predicate type (v2 requires a registry ID and a runtime
 * reference, v1 forbids both), one versioned config subject, and the inner
 * timestamp.
 */
export function parseConfigStatement(payload: Uint8Array): ConfigStatement {
  let decoded: { s: JsonObject; predicate: JsonObject };
  try {
    decoded = decodeStatement(payload, CONFIG_PREDICATE_MEMBERS);
  } catch (err) {
    throw new Error(`decoding config endorsement: ${message(err)}`);
  }
  const { s, predicate } = decoded;
  const type = str(s, "_type");
  const predicateType = str(s, "predicateType");
  if (type !== IN_TOTO_STATEMENT_V1 || (predicateType !== CONFIG_ENDORSEMENT_PREDICATE_TYPE && predicateType !== CONFIG_ENDORSEMENT_PREDICATE_TYPE_V2)) {
    throw new Error("unsupported config endorsement statement type");
  }
  const registryID = str(predicate, "scope");
  const runtimeValue = predicate.get("runtime");
  let runtime: RuntimeReference | undefined;
  if (runtimeValue !== undefined && runtimeValue !== null) {
    const r = object(runtimeValue, "runtime", RUNTIME_MEMBERS);
    runtime = { repo: str(r, "repo"), tag: str(r, "tag"), digest: str(r, "digest") };
  }
  if (predicateType === CONFIG_ENDORSEMENT_PREDICATE_TYPE_V2) {
    validateRegistryID(registryID);
    if (runtime === undefined) throw new Error("config endorsement requires a runtime reference");
    validateRuntimeReference(runtime);
  } else if (runtime !== undefined || registryID !== "") {
    throw new Error("v1 config endorsement cannot contain a runtime reference");
  }
  const subject = singleSubject(s, "config endorsement");
  parseConfigName(subject.name);
  const timestamp = innerTimestamp(predicate, "config endorsement");
  return { type, subject, predicateType, registryID, ...(runtime === undefined ? {} : { runtime }), timestamp };
}

/** The domain-separated canonical core a config endorsement's timestamp covers. */
export function configTimestampInput(s: ConfigStatement): Uint8Array {
  const predicate = new Map<string, JsonValue>();
  if (s.registryID !== "") predicate.set("scope", s.registryID);
  if (s.runtime !== undefined) {
    predicate.set("runtime", new Map<string, JsonValue>([["repo", s.runtime.repo], ["tag", s.runtime.tag], ["digest", s.runtime.digest]]));
  }
  const domain = s.predicateType === CONFIG_ENDORSEMENT_PREDICATE_TYPE_V2 ? CONFIG_FRESHNESS_DOMAIN_V2 : CONFIG_FRESHNESS_DOMAIN;
  return timestampInput(domain, statementCore(s, predicate));
}

/** Strict decode of an artifact-freshness statement: the in-toto v1 type, the artifact predicate, one subject, the inner timestamp. */
export function parseArtifactFreshnessStatement(payload: Uint8Array): ArtifactFreshnessStatement {
  const { s, predicate } = decodeStatement(payload, ARTIFACT_PREDICATE_MEMBERS);
  const type = str(s, "_type");
  const predicateType = str(s, "predicateType");
  const list = s.get("subject");
  const count = list === undefined || list === null ? 0 : Array.isArray(list) ? list.length : -1;
  if (type !== IN_TOTO_STATEMENT_V1 || predicateType !== ARTIFACT_FRESHNESS_PREDICATE_TYPE || count !== 1) {
    throw new Error("unsupported artifact freshness statement");
  }
  const subject = singleSubject(s, "artifact freshness");
  const artifact: FreshnessArtifact = {
    kind: str(predicate, "kind") as ArtifactKind,
    repo: str(predicate, "repo"),
    tag: str(predicate, "tag"),
    name: subject.name,
    digest: subject.digest,
  };
  validateFreshnessArtifact(artifact);
  const timestamp = innerTimestamp(predicate, "artifact freshness");
  return { type, subject, predicateType, artifact, timestamp };
}

/** The domain-separated canonical core an artifact-freshness timestamp covers. */
export function artifactFreshnessTimestampInput(s: ArtifactFreshnessStatement): Uint8Array {
  const predicate = new Map<string, JsonValue>([["kind", s.artifact.kind], ["repo", s.artifact.repo], ["tag", s.artifact.tag]]);
  return timestampInput(ARTIFACT_FRESHNESS_DOMAIN, statementCore(s, predicate));
}

/** The statement with the given predicate members and no freshness, as canonicalization sees it. */
function statementCore(s: ApprovalStatement, predicate: Map<string, JsonValue>): JsonValue {
  return new Map<string, JsonValue>([
    ["_type", s.type],
    ["subject", [new Map<string, JsonValue>([["name", s.subject.name], ["digest", new Map<string, JsonValue>([["sha256", s.subject.digest]])]])]],
    ["predicateType", s.predicateType],
    ["predicate", predicate],
  ]);
}

// ---------------------------------------------------------------- config approvals

/** The pins a config approval must satisfy, and the clock to judge its timestamp by. */
export interface ConfigPolicy {
  /** Canonical /org/project identity; "" leaves it unpinned. */
  readonly identity: string;
  /** "" leaves it unpinned. */
  readonly revision: string;
  /** Lowercase hex SHA-256 of the config bytes; "" leaves it unpinned. */
  readonly digest: string;
  readonly now: Date;
  /** 0 selects the default. */
  readonly maxAgeMs: number;
  /** 0 selects the default. */
  readonly futureSkewMs: number;
  /** The registry IDs the caller accepts; undefined leaves the registry ID unpinned, an empty list is invalid. */
  readonly registryIDs?: readonly string[];
}

export interface ConfigVerified {
  readonly name: string;
  readonly digest: string;
  readonly reference: string;
  readonly signingKeyHint: string;
  readonly approvalTime: Date;
  /** The runtime the endorsement pins, when it carries one (v2). */
  readonly runtime?: RuntimeReference;
  /**
   * The registry ID the approval was accepted under: the certificate's on
   * the certified path, the public registry ID for a key-signed approval
   * under the registry roots, and "" under caller-pinned keys.
   */
  readonly registryID: string;
  /** When the certificate-signed signature was made; undefined for a key-signed approval. */
  readonly signatureTime?: Date;
}

/** Validates the identity, revision, digest and registry ID pins; an empty pin is unset. */
export function validateConfigPins(policy: ConfigPolicy): void {
  if (policy.identity !== "") validateConfigIdentity(policy.identity);
  if (policy.revision !== "") validateRevision(policy.revision);
  if (policy.digest !== "" && !SHA256_DIGEST_RE.test(policy.digest)) throw new Error("digest pin must be lowercase SHA-256");
  if (policy.registryIDs !== undefined) validateRegistryIDs(policy.registryIDs);
}

/** A non-empty list of canonical registry IDs without repeats. */
export function validateRegistryIDs(registryIDs: readonly string[]): void {
  if (registryIDs.length === 0) throw new Error("config registry IDs must not be empty");
  registryIDs.forEach((registryID, i) => {
    validateRegistryID(registryID);
    if (registryIDs.slice(0, i).includes(registryID)) throw new Error("duplicate config registry ID");
  });
}

function configTimePolicy(policy: ConfigPolicy): TimePolicy {
  validateConfigPins(policy);
  return newTimePolicy(policy.now, policy.maxAgeMs, policy.futureSkewMs);
}

export class ConfigVerifier {
  /** The registry root keys; empty when the verifier trusts caller-pinned keys instead. */
  readonly #rootKeys: readonly PinnedKey[];

  /**
   * @internal `keys` sign key-signed approvals. `rootKeys`, when given, are
   * the registry roots that issue registry certificates; under them a
   * registry (v2) approval must be certificate-signed and a key-signed
   * approval is public.
   */
  constructor(
    readonly root: TrustedRoot,
    readonly keys: readonly PinnedKey[],
    rootKeys: readonly PinnedKey[] = [],
  ) {
    if (root.transparencyLogs.length === 0) throw new Error("Rekor trust is required");
    if (keys.length === 0) throw new Error("at least one independently trusted signing key is required");
    this.#rootKeys = [...rootKeys];
  }

  /**
   * Verifies a key-signed config approval: size bounds, the bundle's
   * statement names and pins the config, SHA-256 of `config` equals the
   * subject and the pin (or, with no config bytes, the endorsement is a v2
   * statement that pins the digest alone), the endorsed runtime equals the
   * config's own pin, the bundle verifies under a pinned key, and the
   * predicate's timestamp falls inside the policy window. Under registry
   * roots a registry (v2) statement rejects here: it must be certified.
   */
  verify(config: Uint8Array | undefined, bundleJson: JsonValue, policy: ConfigPolicy): Promise<ConfigVerified> {
    return this.#verify(config, bundleJson, undefined, policy);
  }

  /**
   * Verifies a certificate-signed config approval: the bundle's RFC 3161
   * timestamp fixes the signing time inside the policy window, the signing
   * certificate is authenticated at that time under `issuerDer` and the
   * registry roots, its registry ID equals the statement's, the bundle
   * verifies under the certificate, and the inner timestamp does not follow
   * the signing time by more than the allowed skew.
   */
  verifyCertified(config: Uint8Array | undefined, bundleJson: JsonValue, issuerDer: Uint8Array, policy: ConfigPolicy): Promise<ConfigVerified> {
    if (this.#rootKeys.length === 0) throw new Error("registry root trust is not configured");
    if (issuerDer.length === 0) throw new Error("certified registry verification requires an issuer certificate");
    return this.#verify(config, bundleJson, issuerDer, policy);
  }

  async #verify(config: Uint8Array | undefined, bundleJson: JsonValue, issuerDer: Uint8Array | undefined, policy: ConfigPolicy): Promise<ConfigVerified> {
    if (config !== undefined && (config.length === 0 || config.length > MAX_CONFIG_SIZE)) throw new Error("config size is outside allowed bounds");
    const window = configTimePolicy(policy);
    const bundle = parseBundle(bundleJson);
    const payload = bundle.dsse.payload;
    const s = parseConfigStatement(payload);
    const { identity, revision } = parseConfigName(s.subject.name);
    if ((policy.identity !== "" && identity !== policy.identity) || (policy.revision !== "" && revision !== policy.revision)) {
      throw new Error("config endorsement does not match the pinned identity or revision");
    }
    const hexDigest = s.subject.digest;
    if (policy.digest !== "" && policy.digest !== hexDigest) throw new Error("config endorsement does not match the pinned digest");
    if (config === undefined) {
      if (s.predicateType !== CONFIG_ENDORSEMENT_PREDICATE_TYPE_V2) throw new Error("digest verification requires a v2 config endorsement");
    } else {
      if (toHex(await sha256(config)) !== hexDigest) throw new Error("config bytes do not match the endorsed digest");
      if (s.runtime !== undefined) {
        const runtime = configRuntime(config);
        if (runtime.repo !== s.runtime.repo || runtime.tag !== s.runtime.tag || runtime.digest !== s.runtime.digest) {
          throw new Error("config runtime does not match the endorsed runtime");
        }
      }
    }
    const digest = decodeLowerHex("subject digest", hexDigest, 32);

    let registryID = "";
    let hint: string;
    let signatureTime: Date | undefined;
    if (issuerDer !== undefined) {
      if (s.predicateType !== CONFIG_ENDORSEMENT_PREDICATE_TYPE_V2) throw new Error("certified registry endorsement requires a v2 statement");
      signatureTime = await signedTimestamp(this.root, bundle);
      if (signatureTime > window.latest) throw new Error("signature timestamp is in the future");
      if (bundle.certificate === undefined) throw new Error("certified approval bundle must carry a signing certificate");
      const signing = await verifySigningCertificate(bundle.certificate, issuerDer, this.#rootKeys, signatureTime, validateRegistryID);
      registryID = signing.registryID;
      if (registryID !== s.registryID) throw new Error("certificate registry ID does not match signed registry ID");
      hint = await verifyCertifiedBundle(this.root, bundle, signing.certificate, digest);
    } else {
      if (this.#rootKeys.length !== 0 && s.predicateType === CONFIG_ENDORSEMENT_PREDICATE_TYPE_V2) {
        throw new Error("v2 registry endorsement requires an issuer certificate");
      }
      hint = await verifyKeyedBundle(this.root, bundle, this.keys, digest);
      if (this.#rootKeys.length !== 0) registryID = PUBLIC_REGISTRY_ID;
    }
    if (policy.registryIDs !== undefined && !policy.registryIDs.includes(registryID)) {
      throw new Error("config registry ID is not accepted by the caller");
    }

    let approvalTime: Date;
    try {
      approvalTime = await verifyTimestamp(this.root, s.timestamp, configTimestampInput(s));
      checkTime(window, approvalTime);
    } catch (err) {
      throw new Error(`inner timestamp: ${message(err)}`);
    }
    if (signatureTime !== undefined && approvalTime.getTime() > signatureTime.getTime() + CERTIFICATE_CLOCK_SKEW_MS) {
      throw new Error("approval timestamp follows signature timestamp");
    }
    return {
      name: s.subject.name,
      digest: hexDigest,
      reference: await endorsementReference(payload),
      signingKeyHint: hint,
      approvalTime,
      ...(s.runtime === undefined ? {} : { runtime: s.runtime }),
      registryID,
      ...(signatureTime === undefined ? {} : { signatureTime }),
    };
  }
}

// ---------------------------------------------------------------- artifact freshness approvals

/** Exact release bytes an artifact-freshness approval covers. */
export interface FreshnessArtifact {
  readonly kind: ArtifactKind;
  readonly repo: string;
  readonly tag: string;
  readonly name: string;
  readonly digest: string;
}

/** The manifest name of a runtime release at `tag`. */
export function runtimeArtifactName(tag: string): string {
  return RUNTIME_NAME_PREFIX + tag + RUNTIME_NAME_SUFFIX;
}

/** Whether `name` is the versioned runtime manifest of `tag` (build metadata may follow the tag in the name). */
export function isRuntimeArtifactName(tag: string, name: string): boolean {
  if (!name.startsWith(RUNTIME_NAME_PREFIX) || !name.endsWith(RUNTIME_NAME_SUFFIX)) return false;
  const version = name.slice(RUNTIME_NAME_PREFIX.length, name.length - RUNTIME_NAME_SUFFIX.length);
  return semver.isValid(version) && version === tag + semver.build(version) && name === runtimeArtifactName(version);
}

/**
 * A platform artifact is cvmimage's platform-endorsements.json at a
 * "platform-" tag; a runtime artifact is cvmimage's versioned manifest. The
 * version must be canonical semver and the digest a lowercase SHA-256.
 */
export function validateFreshnessArtifact(a: FreshnessArtifact): void {
  let version = a.tag;
  switch (a.kind) {
    case KIND_PLATFORM:
      if (!a.tag.startsWith(PLATFORM_TAG_PREFIX) || a.repo !== RUNTIME_REPO || a.name !== PLATFORM_ARTIFACT_NAME) {
        throw new Error("platform freshness requires the cvmimage platform artifact");
      }
      version = a.tag.slice(PLATFORM_TAG_PREFIX.length);
      break;
    case KIND_RUNTIME:
      if (a.repo !== RUNTIME_REPO || !isRuntimeArtifactName(a.tag, a.name)) {
        throw new Error("runtime freshness requires the versioned runtime manifest");
      }
      break;
    default:
      throw new Error(`unsupported freshness artifact kind ${JSON.stringify(a.kind)}`);
  }
  if (!semver.isValid(version) || semver.canonical(version) !== version) throw new Error("artifact tag must be a canonical semantic version");
  decodeLowerHex("artifact digest", a.digest, 32);
}

export interface FreshnessPolicy {
  readonly artifact: FreshnessArtifact;
  readonly now: Date;
  /** 0 selects the default. */
  readonly maxAgeMs: number;
  /** 0 selects the default. */
  readonly futureSkewMs: number;
}

export interface FreshnessVerified extends FreshnessArtifact {
  readonly reference: string;
  readonly signingKeyHint: string;
  readonly approvalTime: Date;
}

export class FreshnessVerifier {
  /** @internal */
  constructor(
    readonly root: TrustedRoot,
    readonly keys: readonly PinnedKey[],
  ) {
    if (root.transparencyLogs.length === 0) throw new Error("Rekor trust is required");
    if (keys.length === 0) throw new Error("at least one independently trusted signing key is required");
  }

  /** Verifies an artifact-freshness approval of exactly `policy.artifact` within the policy window. */
  async verify(bundleJson: JsonValue, policy: FreshnessPolicy): Promise<FreshnessVerified> {
    validateFreshnessArtifact(policy.artifact);
    const window = newTimePolicy(policy.now, policy.maxAgeMs, policy.futureSkewMs);
    const bundle = parseBundle(bundleJson);
    const payload = bundle.dsse.payload;
    const s = parseArtifactFreshnessStatement(payload);
    const a = s.artifact;
    const e = policy.artifact;
    if (a.kind !== e.kind || a.repo !== e.repo || a.tag !== e.tag || a.name !== e.name || a.digest !== e.digest) {
      throw new Error("freshness approval does not match the expected artifact");
    }
    const digest = decodeLowerHex("artifact digest", e.digest, 32);
    const hint = await verifyKeyedBundle(this.root, bundle, this.keys, digest);
    let approvalTime: Date;
    try {
      approvalTime = await verifyTimestamp(this.root, s.timestamp, artifactFreshnessTimestampInput(s));
      checkTime(window, approvalTime);
    } catch (err) {
      throw new Error(`inner timestamp: ${message(err)}`);
    }
    return { ...e, reference: await endorsementReference(payload), signingKeyHint: hint, approvalTime };
  }
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
