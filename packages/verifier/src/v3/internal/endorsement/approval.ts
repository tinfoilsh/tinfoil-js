/**
 * Approvals signed with Tinfoil's pinned keys: config endorsements and
 * artifact-freshness statements. Each is a key-signed bundle over an in-toto
 * statement whose predicate carries an RFC 3161 timestamp of the statement's
 * canonical core.
 */
import { notImplemented } from "../../errors.js";
import type { JsonValue } from "../json/index.js";
import type { PinnedKey } from "../sigstore/keyed.js";
import type { TrustedRoot } from "../sigstore/trusted-root.js";

export const CONFIG_ENDORSEMENT_PREDICATE_TYPE = "https://tinfoil.sh/predicate/config-endorsement/v1";
export const ARTIFACT_FRESHNESS_PREDICATE_TYPE = "https://tinfoil.sh/predicate/artifact-freshness/v1";
export const MAX_CONFIG_SIZE = 1 << 20;

export const KIND_PLATFORM = "platform";
export const KIND_RUNTIME = "runtime";
export type ArtifactKind = typeof KIND_PLATFORM | typeof KIND_RUNTIME;
export const PLATFORM_ARTIFACT_NAME = "platform-endorsements.json";

/** Tinfoil's embedded public signing keys. */
export function publicSigningKeys(): Promise<PinnedKey[]>;
export function publicSigningKeys(): Promise<PinnedKey[]> {
  return notImplemented("endorsement.publicSigningKeys");
}

/** The pins a config approval must satisfy, and the clock to judge its timestamp by. */
export interface ConfigPolicy {
  /** Canonical /org/project identity. */
  readonly identity: string;
  readonly revision: string;
  /** Lowercase hex SHA-256 of the config bytes. */
  readonly digest: string;
  readonly now: Date;
  readonly maxAgeMs: number;
  readonly futureSkewMs: number;
}

export interface ConfigVerified {
  readonly name: string;
  readonly digest: string;
  readonly reference: string;
  readonly signingKeyHint: string;
  readonly approvalTime: Date;
}

/** Validates the identity, revision and digest pins. */
export function validateConfigPins(policy: ConfigPolicy): void {
  return notImplemented("endorsement.validateConfigPins");
}

/** Splits a versioned config name into identity and revision. */
export function parseConfigName(name: string): { identity: string; revision: string } {
  return notImplemented("endorsement.parseConfigName");
}

export class ConfigVerifier {
  /** @internal */
  constructor(readonly root: TrustedRoot, readonly keys: readonly PinnedKey[]) {}

  /**
   * Verifies a config approval: size bounds, the bundle's statement names and
   * pins the config, SHA-256 of `config` equals the subject and the pin, the
   * key-signed bundle verifies, and the predicate's timestamp falls inside the
   * policy window.
   */
  async verify(config: Uint8Array, bundle: JsonValue, policy: ConfigPolicy): Promise<ConfigVerified> {
    return notImplemented("ConfigVerifier.verify");
  }
}

/** Exact release bytes an artifact-freshness approval covers. */
export interface FreshnessArtifact {
  readonly kind: ArtifactKind;
  readonly repo: string;
  readonly tag: string;
  readonly name: string;
  readonly digest: string;
}

export function validateFreshnessArtifact(a: FreshnessArtifact): void {
  return notImplemented("endorsement.validateFreshnessArtifact");
}

export interface FreshnessPolicy {
  readonly artifact: FreshnessArtifact;
  readonly now: Date;
  readonly maxAgeMs: number;
  readonly futureSkewMs: number;
}

export interface FreshnessVerified extends FreshnessArtifact {
  readonly reference: string;
  readonly signingKeyHint: string;
  readonly approvalTime: Date;
}

export class FreshnessVerifier {
  /** @internal */
  constructor(readonly root: TrustedRoot, readonly keys: readonly PinnedKey[]) {}

  /** Verifies an artifact-freshness approval of exactly `policy.artifact` within the policy window. */
  async verify(bundle: JsonValue, policy: FreshnessPolicy): Promise<FreshnessVerified> {
    return notImplemented("FreshnessVerifier.verify");
  }
}
