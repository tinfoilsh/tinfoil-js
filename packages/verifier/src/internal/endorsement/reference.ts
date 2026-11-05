/** Release references and the identity of an authenticated artifact. */

/** A GitHub "owner/name" repository slug. */
export const REPO_NAME_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
/** A lowercase 40-hex Git commit. */
export const GIT_COMMIT_RE = /^[0-9a-f]{40}$/;
/** A lowercase 64-hex SHA-256. */
export const SHA256_DIGEST_RE = /^[0-9a-f]{64}$/;

/**
 * owner/name[@tag][@sha256:digest]. The tag group is lazy, so "@sha256:…"
 * alone reads as a digest rather than a tag.
 */
const REF_RE = /^([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)(?:@([^@\s~^:?*[\\]+))??(?:@sha256:([0-9a-f]{64}))?$/;

/** A pinned `owner/name[@tag][@sha256:digest]` reference. */
export interface Reference {
  readonly repo: string;
  readonly tag: string;
  readonly digest: string;
}

/** Validates `owner/name[@tag][@sha256:digest]` and returns its parts; absent parts are "". */
export function parseReference(ref: string): Reference {
  const m = REF_RE.exec(ref);
  if (m === null) throw new Error(`invalid release reference ${JSON.stringify(ref)}: want owner/name[@tag][@sha256:digest]`);
  return { repo: m[1]!, tag: m[2] ?? "", digest: m[3] ?? "" };
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

/** Every field well-formed: a repository slug, a non-empty tag, a Git commit, a subject name, a SHA-256. */
export function validateAuthenticatedArtifact(a: AuthenticatedArtifact): void {
  if (!REPO_NAME_RE.test(a.repo)) throw new Error("authenticated artifact repository is invalid");
  if (a.tag === "") throw new Error("authenticated artifact tag is empty");
  if (!GIT_COMMIT_RE.test(a.commit)) throw new Error("authenticated artifact commit is malformed");
  if (a.subjectName === "") throw new Error("authenticated artifact subject name is empty");
  if (!SHA256_DIGEST_RE.test(a.digest)) throw new Error("authenticated artifact digest is malformed");
}

/** The repository whose runtime and platform releases are pinned by numeric id. */
export const RUNTIME_REPO_ID = "902195777";
export const TINFOIL_ORGANIZATION_ID = "168487856";
export const FRESHNESS_WITNESS_REPO = "tinfoilsh/freshness-witness";
