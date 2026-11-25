/**
 * The trust argument of an enclave client: who vouches for the config that
 * the enclave runs. Each variant is one object told apart by `kind`, so a
 * client can't be built without naming what it trusts, and settings that
 * only make sense together can't be mixed. The client turns its trust
 * argument into the verifier's config trust and the pin that each
 * verification is made against.
 */
import type { ConfigEndorsement, ConfigTrust, Pin } from "@tinfoilsh/verifier";
import { ConfigurationError, describeKind } from "./errors.js";

/**
 * Who vouches for the config that an enclave runs: one of {@link RepoPin},
 * {@link ProjectPin}, {@link SignedBy}, {@link AuthorizedBy},
 * {@link EmbeddedConfig} or {@link EitherPin}. Only `repoPin` and `eitherPin`
 * accept attestation-collaterals/v2; every other variant requires
 * attestation-collaterals/v3. An unknown `kind`, or a variant without a
 * member that it requires, is a {@link ConfigurationError}.
 */
export type Trust = RepoPin | ProjectPin | SignedBy | AuthorizedBy | EmbeddedConfig | EitherPin;

/** Trusts v2 collateral for `repo`, a GitHub repository `owner/name[@tag][@sha256:digest]`, which must not be empty. */
export interface RepoPin {
  readonly kind: "repoPin";
  readonly repo: string;
}

/**
 * Trusts v3 collateral for `project`, a config registry project
 * `org/project[@revision][@sha256:digest]` that must not be empty, that one
 * of the trusted registries endorses.
 */
export interface ProjectPin {
  readonly kind: "projectPin";
  readonly project: string;
  /**
   * The trusted registries; undefined and empty differ. Undefined trusts
   * Tinfoil's public registry alone. A non-empty list trusts exactly the
   * registries that it names, in place of the public registry; to trust a
   * private registry alongside the public one, list `PUBLIC_REGISTRY_ID`
   * from `@tinfoilsh/verifier` too. An empty list is a
   * {@link ConfigurationError}, so that an empty list that the application
   * computed fails closed rather than widening trust to the public registry.
   */
  readonly registryIDs?: readonly string[];
}

/**
 * Trusts v3 configs whose endorsements the caller's `keys`, PEM-encoded
 * P-256 public keys, sign in place of Tinfoil's registry root. `keys` must
 * not be empty. `project`, a config registry project
 * `org/project[@revision][@sha256:digest]`, optionally restricts the configs
 * that are accepted; undefined or "" accepts any config that `keys` sign.
 */
export interface SignedBy {
  readonly kind: "signedBy";
  readonly keys: readonly string[];
  readonly project?: string;
}

/**
 * Trusts v3 configs that `authorize` accepts, in place of a registry
 * endorsement. `authorize` receives detached, untrusted material and must
 * throw for config bytes that it doesn't authorize; it may run
 * concurrently. Runtime, platform and hardware checks still apply. Approval
 * authenticates no registry name or timestamp, so this variant has no pin.
 */
export interface AuthorizedBy {
  readonly kind: "authorizedBy";
  readonly authorize: (endorsement: ConfigEndorsement) => void | Promise<void>;
}

/**
 * Trusts v3 collateral for exactly the config `bytes` that the caller
 * supplies, which must come from trusted client configuration. `name`
 * optionally associates them with an /org/project/revision identity. It has
 * no pin, because a pin would only compare the caller's input against the
 * caller's input. The bytes must be a JSON config. The attestation must
 * still prove every container build that the config requires.
 */
export interface EmbeddedConfig {
  readonly kind: "embeddedConfig";
  readonly name?: string;
  readonly bytes: Uint8Array;
}

/**
 * Trusts v2 collateral for `repo` or v3 collateral for `project`, as
 * {@link RepoPin} and {@link ProjectPin} do; both must be set. It exists for
 * the migration from v2 to v3 collateral and will be removed with v2.
 */
export interface EitherPin {
  readonly kind: "eitherPin";
  readonly repo: string;
  readonly project: string;
}

/**
 * @internal The verifier's config trust and the pin that each verification
 * is made against, for `trust`. It checks only what the variant itself
 * requires; the verifier checks the values when it is built.
 */
export function verifierInputs(trust: Trust): { config: ConfigTrust | undefined; pin: Pin } {
  if (typeof trust !== "object" || trust === null) throw new ConfigurationError("trust is required");
  switch (trust.kind) {
    case "repoPin":
      required(trust, "repoPin", "repo");
      return { config: undefined, pin: { repo: trust.repo } };
    case "projectPin": {
      required(trust, "projectPin", "project");
      const pin = { project: trust.project };
      if (trust.registryIDs === undefined) return { config: undefined, pin };
      if (Array.isArray(trust.registryIDs) && trust.registryIDs.length === 0) {
        throw new ConfigurationError("projectPin registryIDs must not be empty; leave it undefined to trust the public registry");
      }
      return { config: { kind: "registries", ids: trust.registryIDs }, pin };
    }
    case "signedBy":
      return { config: { kind: "configSigningKeys", keys: trust.keys }, pin: { project: trust.project === undefined ? "" : trust.project } };
    case "authorizedBy":
      return { config: { kind: "configAuthorizer", authorize: trust.authorize }, pin: {} };
    case "embeddedConfig":
      return { config: { kind: "embeddedConfig", ...(trust.name === undefined ? {} : { name: trust.name }), bytes: trust.bytes }, pin: {} };
    case "eitherPin":
      required(trust, "eitherPin", "repo");
      required(trust, "eitherPin", "project");
      return { config: undefined, pin: { repo: trust.repo, project: trust.project } };
    default: {
      throw new ConfigurationError(
        `trust must have kind "repoPin", "projectPin", "signedBy", "authorizedBy", "embeddedConfig" or "eitherPin", not ${describeKind((trust as { kind?: unknown }).kind)}`,
      );
    }
  }
}

/** Refuses a variant whose `member` isn't a non-empty string. */
function required(trust: object, kind: string, member: string): void {
  const value = (trust as Record<string, unknown>)[member];
  if (typeof value !== "string" || value === "") throw new ConfigurationError(`${kind} requires ${member}`);
}

/**
 * @internal A frozen copy of `trust` that shares no array or bytes with it,
 * so that changing the copy, or the caller's original, has no effect on the
 * other. Keys and functions are shared.
 */
export function cloneTrust(trust: Trust): Trust {
  switch (trust.kind) {
    case "projectPin":
      return Object.freeze({ ...trust, ...(trust.registryIDs === undefined ? {} : { registryIDs: Object.freeze([...trust.registryIDs]) }) });
    case "signedBy":
      return Object.freeze({ ...trust, keys: Object.freeze([...trust.keys]) });
    case "embeddedConfig":
      return Object.freeze({ ...trust, bytes: trust.bytes.slice() });
    default:
      return Object.freeze({ ...trust });
  }
}
