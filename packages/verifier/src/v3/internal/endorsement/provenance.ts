import { NotImplementedError } from "../../errors.js";
import type { JsonValue } from "../json/index.js";
import type { ExpectedSevSnp, ExpectedTdx } from "../../measurement.js";

/** Predicate type of a release's multi-platform code measurement. */
export const MULTI_PLATFORM_PREDICATE_TYPE = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1";

/** A pinned `owner/name[@tag][@sha256:digest]` reference. */
export interface Reference {
  readonly repo: string;
  readonly tag?: string;
  readonly digest?: string;
}

/** A Sigstore artifact whose provenance was authenticated. */
export interface AuthenticatedArtifact {
  readonly repo: string;
  readonly tag: string;
  readonly digest: string;
}

/** Authenticated code provenance: the registers the release fixes on each platform. */
export interface Code extends AuthenticatedArtifact {
  readonly sevSnp: ExpectedSevSnp;
  readonly tdx: ExpectedTdx;
}

/** Authenticated platform-endorsements artifact. TODO(v3): carry the parsed policy artifact. */
export type PlatformEndorsements = AuthenticatedArtifact;

/** Validates `owner/name[@tag][@sha256:digest]` and returns its parts. */
export function parseReference(ref: string): Reference {
  void ref;
  throw new NotImplementedError("endorsement.parseReference");
}

/** Authenticates Sigstore bundles against a trusted root. */
export class ProvenanceClient {
  private constructor() {}

  /** A client using the embedded production Sigstore trusted root. */
  static async default(): Promise<ProvenanceClient> {
    throw new NotImplementedError("ProvenanceClient.default");
  }

  /** A client using the given Sigstore trusted-root JSON. */
  static async fromJSON(trustedRootJSON: Uint8Array): Promise<ProvenanceClient> {
    void trustedRootJSON;
    throw new NotImplementedError("ProvenanceClient.fromJSON");
  }

  /**
   * Verifies code provenance against the pinned reference. Pins in `ref` take
   * precedence over the document's tag and digest hints.
   */
  async authenticateCode(bundle: JsonValue, ref: Reference, tag: string, hexDigest: string): Promise<Code> {
    void bundle;
    void ref;
    void tag;
    void hexDigest;
    throw new NotImplementedError("ProvenanceClient.authenticateCode");
  }

  /** Verifies the platform-endorsements artifact's provenance. */
  async authenticatePlatformEndorsements(
    bundle: JsonValue,
    repo: string,
    tag: string,
    hexDigest: string,
    format: string,
  ): Promise<PlatformEndorsements> {
    void bundle;
    void repo;
    void tag;
    void hexDigest;
    void format;
    throw new NotImplementedError("ProvenanceClient.authenticatePlatformEndorsements");
  }
}
