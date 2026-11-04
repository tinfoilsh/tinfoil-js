/**
 * Certificate-signed bundle verification: the Sigstore library proves the
 * chain, certificate-transparency, log inclusion, timestamps and the DSSE
 * signature; this module adds the signing-identity policy and reads the
 * source-repository claims the verifier binds artifacts to.
 *
 * What the library's `verifyDsse` enforces, so this module does not repeat it:
 * the leaf chains to a certificate authority of the root valid at its
 * notBefore; the SCT extension is present, non-empty, names no log twice,
 * and at least one SCT verifies against a CT log valid at its time; at least
 * one log entry, no more than 32, none duplicated; an inclusion proof on
 * every entry (Merkle path and signed checkpoint) and the inclusion promise
 * of the first, when present, under the log's key; the certificate valid at
 * every entry's integration time and at every RFC 3161 timestamp, each of
 * which verifies under a timestamp authority of the root; exactly one DSSE
 * signature, verified over the pre-authentication encoding under the
 * certificate key; every entry of kind "dsse" with a body consistent with the
 * envelope.
 *
 * What the library does not enforce: that some verified time anchors the
 * signature. A bare integration time is unsigned (the inclusion proof covers
 * the entry body only), so this module requires the first entry's inclusion
 * promise, which signs its integration time, or an RFC 3161 timestamp.
 */
import { SigstoreVerifier, type SigstoreBundle, type TrustedRoot as LibraryTrustedRoot, type VerificationPolicy, type X509Certificate } from "@freedomofpress/sigstore-browser";
import { map, object, str } from "../json/decode.js";
import { serialize, strictParse, type JsonObject, type JsonValue } from "../json/index.js";
import { IN_TOTO_PAYLOAD_TYPE, type Bundle } from "./bundle.js";
import type { TrustedRoot } from "./trusted-root.js";

export const GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com";
export const RUNNER_ENVIRONMENT_GITHUB_HOSTED = "github-hosted";

/** The claims a GitHub Actions signing certificate carries. */
export interface SigningIdentity {
  /** The SAN URI: https://github.com/<repo>/.github/workflows/<file>@<ref>. */
  readonly subjectAlternativeName: string;
  readonly issuer: string;
  readonly runnerEnvironment: string;
  readonly sourceRepositoryIdentifier: string;
  readonly sourceRepositoryOwnerIdentifier: string;
  readonly sourceRepositoryRef: string;
  readonly sourceRepositoryDigest: string;
}

/** What verification proved about a certificate-signed bundle. */
export interface VerifiedBundle {
  readonly identity: SigningIdentity;
  readonly payload: Uint8Array;
  /** The first log entry's integration time, present only when its inclusion promise verified. */
  readonly earliestLogTime?: Date;
}

/**
 * Verifies a certificate-signed DSSE bundle against `root`: the certificate
 * chain, at least one SCT, at least one log entry with inclusion proven, a
 * verified observer timestamp (the first entry's inclusion promise or an
 * RFC 3161 timestamp), the DSSE signature, that no two SCTs come from the
 * same log, that the SAN matches `sanPattern`, the issuer is GitHub and the
 * runner is GitHub-hosted, and that the statement's subject carries
 * `digestHex` (as subject 0, or as the subject named `subjectName`).
 */
export async function verifyCertificateBundle(
  root: TrustedRoot,
  bundle: Bundle,
  sanPattern: RegExp,
  digestHex: string,
  subjectName?: string,
): Promise<VerifiedBundle> {
  if (bundle.certificate === undefined) throw new Error("bundle has no signing certificate");
  if (bundle.dsse.payloadType !== IN_TOTO_PAYLOAD_TYPE) {
    throw new Error(`unsupported DSSE payload type ${JSON.stringify(bundle.dsse.payloadType)}`);
  }
  if (!SHA256_HEX.test(digestHex)) throw new Error("expected artifact digest is not hex SHA-256");

  const verifier = new SigstoreVerifier({ ctlogThreshold: 1, tlogThreshold: 1, tsaThreshold: 0 });
  try {
    await verifier.loadSigstoreRoot(plain(root.json) as LibraryTrustedRoot);
  } catch (err) {
    throw new Error(`loading trusted root: ${message(err)}`);
  }
  const policy = new WorkflowIdentityPolicy(sanPattern);
  try {
    await verifier.verifyDsse(plain(bundle.json) as SigstoreBundle, policy);
  } catch (err) {
    throw new Error(`verifying bundle: ${message(err)}`);
  }
  const identity = policy.identity;
  if (identity === undefined) throw new Error("verifying bundle: the signing certificate was not checked");

  // The signature must be anchored by a time the library verified: the first
  // entry's promise (a signature over its integration time) or an RFC 3161
  // timestamp. A bare integration time is the bundle's own claim.
  const first = bundle.tlogEntries[0];
  const promised = first !== undefined && first.inclusionPromise !== undefined && first.integratedTime !== undefined;
  if (!promised && bundle.rfc3161Timestamps.length === 0) {
    throw new Error("verifying bundle: no verified observer timestamp (no inclusion promise on the first log entry and no RFC 3161 timestamp)");
  }

  enforceSubject(statementSubjects(bundle.dsse.payload), digestHex, subjectName ?? "");

  return {
    identity,
    payload: bundle.dsse.payload,
    ...(promised ? { earliestLogTime: new Date(Number(first.integratedTime) * 1000) } : {}),
  };
}

/**
 * Builds the anchored SAN pattern `^https://github\.com/<repo>/\.github/workflows/<workflow>@<ref>$`.
 * `repo` is a literal and is escaped; `workflowPattern` and `refPattern` are
 * regular-expression fragments, each grouped so that an alternation inside
 * one cannot escape the anchors around it.
 */
export function workflowIdentityPattern(repo: string, workflowPattern: string, refPattern: string): RegExp {
  const literal = repo.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^https://github\\.com/${literal}/\\.github/workflows/(?:${workflowPattern})@(?:${refPattern})$`);
}

const SHA256_HEX = /^[0-9a-fA-F]{64}$/;

/**
 * The certificate policy the library applies before proving the chain: the
 * SAN URI matches the workflow pattern, every OIDC issuer extension names
 * GitHub Actions, and the runner environment is GitHub-hosted. Records the
 * identity read from the certificate it accepted.
 */
class WorkflowIdentityPolicy implements VerificationPolicy {
  identity: SigningIdentity | undefined;

  constructor(private readonly sanPattern: RegExp) {}

  verify(cert: X509Certificate): void {
    const san = cert.extSubjectAltName?.uri;
    if (san === undefined) throw new Error("signing certificate has no URI subject alternative name");
    if (!this.sanPattern.test(san)) {
      throw new Error(`signing identity ${JSON.stringify(san)} does not match the expected workflow identity`);
    }
    const issuerV1 = cert.extFulcioIssuerV1?.issuer;
    const issuerV2 = cert.extFulcioIssuerV2?.issuer;
    const issuer = issuerV2 ?? issuerV1;
    if (issuer === undefined) throw new Error("signing certificate has no OIDC issuer extension");
    if (issuer !== GITHUB_OIDC_ISSUER || (issuerV1 !== undefined && issuerV1 !== GITHUB_OIDC_ISSUER)) {
      throw new Error(`signing certificate issuer ${JSON.stringify(issuer)} is not GitHub Actions`);
    }
    const runner = cert.extRunnerEnvironment?.runnerEnvironment;
    if (runner !== RUNNER_ENVIRONMENT_GITHUB_HOSTED) {
      throw new Error(`signing certificate runner environment ${JSON.stringify(runner ?? "")} is not GitHub-hosted`);
    }
    this.identity = {
      subjectAlternativeName: san,
      issuer,
      runnerEnvironment: runner,
      sourceRepositoryIdentifier: cert.extSourceRepositoryIdentifier?.sourceRepositoryIdentifier ?? "",
      sourceRepositoryOwnerIdentifier: cert.extSourceRepositoryOwnerIdentifier?.sourceRepositoryOwnerIdentifier ?? "",
      sourceRepositoryRef: cert.extSourceRepositoryRef?.sourceRepositoryRef ?? "",
      sourceRepositoryDigest: cert.extSourceRepositoryDigest?.sourceRepositoryDigest ?? "",
    };
  }
}

const STATEMENT_MEMBERS = ["_type", "subject", "predicateType", "predicate"];
const SUBJECT_MEMBERS = ["name", "digest"];

interface Subject {
  readonly name: string;
  readonly sha256: string;
}

/** Parses the signed payload as an in-toto statement and returns its subjects; a null subject rejects. */
function statementSubjects(payload: Uint8Array): Subject[] {
  let statement: JsonObject;
  let subjects: readonly JsonValue[];
  try {
    const value = strictParse(payload);
    if (value === null) throw new Error("statement is null");
    statement = object(value, "statement", STATEMENT_MEMBERS);
    const list = statement.get("subject");
    if (list === undefined || list === null) {
      subjects = [];
    } else if (Array.isArray(list)) {
      subjects = list;
    } else {
      throw new Error("subject is not an array");
    }
  } catch (err) {
    throw new Error(`parsing in-toto statement: ${message(err)}`);
  }
  return subjects.map((s, i) => {
    if (s === null) throw new Error(`in-toto statement subject ${i} is null`);
    const subject = object(s, `subject[${i}]`, SUBJECT_MEMBERS);
    const digests = map(subject, "digest", (v, algorithm) => {
      if (v === null) return "";
      if (typeof v !== "string") throw new Error(`in-toto statement subject ${i} digest ${JSON.stringify(algorithm)} is not a string`);
      return v;
    });
    return { name: str(subject, "name"), sha256: digests.get("sha256") ?? "" };
  });
}

/**
 * The subject rule: with no name, subject 0 must carry the digest; with a
 * name, exactly one subject carries that name and it must carry the digest.
 * Digests compare case-insensitively.
 */
function enforceSubject(subjects: readonly Subject[], digestHex: string, subjectName: string): void {
  if (subjectName === "") {
    const first = subjects[0];
    if (first === undefined) throw new Error("in-toto statement has no subject");
    if (!sameDigest(first.sha256, digestHex)) {
      throw new Error(`subject[0] digest ${JSON.stringify(first.sha256)} does not match expected artifact digest ${JSON.stringify(digestHex)}`);
    }
    return;
  }
  let matches = 0;
  for (const subject of subjects) {
    if (subject.name !== subjectName) continue;
    if (!sameDigest(subject.sha256, digestHex)) {
      throw new Error(`subject ${JSON.stringify(subjectName)} digest does not match expected artifact digest`);
    }
    matches++;
  }
  if (matches !== 1) {
    throw new Error(`in-toto statement must name subject ${JSON.stringify(subjectName)} exactly once, found ${matches}`);
  }
}

function sameDigest(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}

/** The plain-object form of a parsed value (trusted root or bundle), as the library reads it. */
function plain(json: JsonValue): unknown {
  return JSON.parse(new TextDecoder().decode(serialize(json))) as unknown;
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
