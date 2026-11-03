/** Release references and the identity of an authenticated artifact. */
import { notImplemented } from "../../errors.js";

/** A pinned `owner/name[@tag][@sha256:digest]` reference. */
export interface Reference {
  readonly repo: string;
  readonly tag: string;
  readonly digest: string;
}

/** Validates `owner/name[@tag][@sha256:digest]` and returns its parts; absent parts are "". */
export function parseReference(ref: string): Reference {
  return notImplemented("endorsement.parseReference");
}

/** The release an authenticated bundle came from, as proven by its signing certificate and statement. */
export interface AuthenticatedArtifact {
  readonly repo: string;
  readonly tag: string;
  /** Lowercase 40-hex Git commit. */
  readonly commit: string;
  readonly subjectName: string;
  /** Lowercase hex. */
  readonly digest: string;
}

/** The repository whose runtime and platform releases are pinned by numeric id. */
export const RUNTIME_REPO_ID = "902195777";
export const TINFOIL_ORGANIZATION_ID = "168487856";
export const FRESHNESS_WITNESS_REPO = "tinfoilsh/freshness-witness";
