/**
 * Provenance of the code and platform releases: certificate-signed Sigstore
 * bundles from the releasing repository's GitHub Actions workflow.
 */
import { notImplemented } from "../../errors.js";
import type { JsonValue } from "../json/index.js";
import type { ExpectedSevSnp, ExpectedTdx } from "../../measurement.js";
import type { Artifact } from "../policy/artifact.js";
import type { Shape } from "../policy/shape.js";
import type { TrustedRoot } from "../sigstore/trusted-root.js";
import type { AuthenticatedArtifact, Reference } from "./reference.js";

/** Predicate type of a release's multi-platform code measurement. */
export const MULTI_PLATFORM_PREDICATE_TYPE = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1";
/** The repository that publishes platform endorsements. */
export const PLATFORM_ENDORSEMENTS_REPO = "tinfoilsh/cvmimage";

/** Authenticated code provenance: the registers the release fixes on each platform, and its VM shape. */
export interface Code extends AuthenticatedArtifact {
  readonly sevSnp: ExpectedSevSnp;
  readonly tdx: ExpectedTdx;
  readonly shape: Shape;
}

/** The authenticated platform-endorsements artifact. */
export interface PlatformEndorsements extends AuthenticatedArtifact {
  readonly artifact: Artifact;
}

/** Authenticates provenance bundles against one trusted root. */
export class ProvenanceClient {
  /** @internal */
  constructor(readonly root: TrustedRoot) {}

  /** A client on the embedded production trusted root. */
  static async default(): Promise<ProvenanceClient> {
    return notImplemented("ProvenanceClient.default");
  }

  /** A client on the given trusted-root JSON. */
  static async fromJSON(trustedRootJSON: Uint8Array): Promise<ProvenanceClient> {
    return notImplemented("ProvenanceClient.fromJSON");
  }

  /**
   * Verifies code provenance: a bundle signed by a tag-ref workflow of
   * `ref.repo`, whose statement carries `digest` and the multi-platform
   * predicate. Pins in `ref` override the `tag` and `digest` hints.
   */
  async authenticateCode(bundle: JsonValue, ref: Reference, tag: string, hexDigest: string): Promise<Code> {
    return notImplemented("ProvenanceClient.authenticateCode");
  }

  /**
   * Verifies the platform-endorsements artifact: `repo` must equal
   * PLATFORM_ENDORSEMENTS_REPO (a document naming any other repository is
   * rejected before any verification), the bundle must be signed by that
   * repository's platform-release workflow at a platform tag, and the
   * predicate type and artifact format must both equal `format`. The
   * artifact is parsed from the signed payload bytes.
   */
  async authenticatePlatformEndorsements(bundle: JsonValue, repo: string, tag: string, hexDigest: string, format: string): Promise<PlatformEndorsements> {
    return notImplemented("ProvenanceClient.authenticatePlatformEndorsements");
  }
}
