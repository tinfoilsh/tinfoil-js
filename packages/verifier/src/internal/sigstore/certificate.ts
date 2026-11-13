/**
 * Certificate-signed bundle verification: the Sigstore library proves the
 * chain, certificate-transparency, log inclusion, timestamps and the DSSE
 * signature; this module adds the signing-identity policy and reads the
 * source-repository claims the verifier binds artifacts to.
 *
 * What the library's `verifyDsse` enforces, so this module does not repeat it:
 * a bundle of media type version 0.2 or 0.3 with at least one log entry and
 * no more than 32; the signing-identity policy before any proof; for every
 * entry from a log of the root, an inclusion proof (Merkle path and signed
 * checkpoint), the inclusion promise when present under the log's key valid
 * at the integration time, the certificate valid at that time, and a body
 * consistent with the envelope, with at least one log operator verified
 * (entries from logs the root does not name are ignored); every RFC 3161
 * timestamp verifies under a timestamp authority of the root; some verified
 * time anchors the signature, a promise-signed integration time or an
 * RFC 3161 timestamp, and the leaf chains to a certificate authority of the
 * root at every such time; the SCT extension is present, non-empty, names no
 * log twice, and every SCT verifies against a CT log valid at its time;
 * exactly one DSSE signature, verified over the pre-authentication encoding
 * under the certificate key; every entry of kind "dsse".
 *
 * The library does not check extended key usage, so it is checked here for
 * code signing along the whole path: the leaf before the library runs, and
 * the certificate authorities by leaving out of the root handed to the
 * library any certificate whose extended key usage does not allow it.
 *
 * The library accepts the anchoring promise on any entry of a known log and
 * does not report which entries it verified, so `verifiedLogTime` is proven
 * here: the first entry's promise is verified under its log's key from the
 * root, or else an RFC 3161 timestamp must be present.
 */
import { SigstoreVerifier, type SigstoreBundle, type TrustedRoot as LibraryTrustedRoot, type VerificationPolicy, type X509Certificate } from "@freedomofpress/sigstore-browser";
import { map, object, str } from "../json/decode.js";
import { serialize, strictParse, type JsonObject, type JsonValue } from "../json/index.js";
import { IN_TOTO_PAYLOAD_TYPE, type Bundle } from "./bundle.js";
import { expectSequence, extension, parseCertificate, X509Error, type Certificate } from "../x509/certificate.js";
import { decode, DerError, oid } from "../x509/der.js";
import { promisedLogTime } from "./keyed.js";
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
  /** The first log entry's integration time, present only when its inclusion promise verified here under the log's key. */
  readonly verifiedLogTime?: Date;
}

/**
 * Verifies a certificate-signed DSSE bundle against `root`: the certificate
 * chain, extended key usage allowing code signing on every certificate of
 * the chain that carries one, at least one SCT, at least one log entry with inclusion proven, a
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

  let leaf: Certificate;
  try {
    leaf = parseCertificate(bundle.certificate);
  } catch (err) {
    throw new Error(`parsing signing certificate: ${message(err)}`);
  }
  if (!allowsCodeSigning(leaf)) throw new Error("signing certificate's extended key usage does not allow code signing");

  const libraryRoot = codeSigningRoot(root);
  const verifier = new SigstoreVerifier({ ctlogThreshold: 1, tlogThreshold: 1, tsaThreshold: 0 });
  try {
    await verifier.loadSigstoreRoot(libraryRoot.json as LibraryTrustedRoot);
  } catch (err) {
    throw new Error(`loading trusted root: ${message(err)}`);
  }
  const policy = new WorkflowIdentityPolicy(sanPattern);
  try {
    await verifier.verifyDsse(plain(bundle.json) as SigstoreBundle, policy);
  } catch (err) {
    const note =
      libraryRoot.excluded === 0
        ? ""
        : ` (${libraryRoot.excluded} certificate authority certificate(s) not used: extended key usage does not allow code signing)`;
    throw new Error(`verifying bundle: ${message(err)}${note}`);
  }
  const identity = policy.identity;
  if (identity === undefined) throw new Error("verifying bundle: the signing certificate was not checked");

  // The signature must be anchored by a verified time. The library requires
  // one but does not say which entry supplied it, and it ignores entries from
  // logs the root does not list, so the first entry's promise is verified
  // here under its log's key before its time is reported; without one, an
  // RFC 3161 timestamp must be present. A bare integration time is the
  // bundle's own claim.
  let verifiedLogTime: Date | undefined;
  try {
    verifiedLogTime = await promisedLogTime(root, bundle.tlogEntries);
  } catch (err) {
    throw new Error(`verifying bundle: ${message(err)}`);
  }
  if (verifiedLogTime === undefined && bundle.rfc3161Timestamps.length === 0) {
    throw new Error("verifying bundle: no verified observer timestamp (no inclusion promise on the first log entry and no RFC 3161 timestamp)");
  }

  enforceSubject(statementSubjects(bundle.dsse.payload), digestHex, subjectName ?? "");

  return {
    identity,
    payload: bundle.dsse.payload,
    ...(verifiedLogTime === undefined ? {} : { verifiedLogTime }),
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

/** One in-toto subject: its name and its sha256 digest ("" when it carries none). */
export interface Subject {
  readonly name: string;
  readonly sha256: string;
}

/** Parses the signed payload as an in-toto statement and returns its subjects; a null subject rejects. */
export function statementSubjects(payload: Uint8Array): Subject[] {
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

const OID_EXT_KEY_USAGE = "2.5.29.37";
const OID_KP_CODE_SIGNING = "1.3.6.1.5.5.7.3.3";
const OID_KP_ANY = "2.5.29.37.0";

/**
 * Whether `cert` may stand on a code-signing certificate path: it carries no
 * extended key usage, or one naming code signing or any purpose. This is the
 * per-certificate rule of Go's crypto/x509 chain verification with code
 * signing as the requested usage. A malformed or empty extension rejects.
 */
export function allowsCodeSigning(cert: Certificate): boolean {
  const ext = extension(cert, OID_EXT_KEY_USAGE);
  if (ext === undefined) return true;
  let purposes: string[];
  try {
    purposes = expectSequence(decode(ext.value), "ExtKeyUsage").map(oid);
  } catch (err) {
    if (err instanceof DerError || err instanceof X509Error) return false;
    throw err;
  }
  return purposes.some((p) => p === OID_KP_CODE_SIGNING || p === OID_KP_ANY);
}

/**
 * The library's form of `root`, keeping only the certificate-authority
 * certificates whose extended key usage allows code signing, so that no
 * certificate path the library builds passes through one that does not.
 * When a certificate authority's root does not allow it, every path through
 * that authority fails, so the whole authority is left out; the library
 * drops an authority with no certificates. Otherwise only the intermediates
 * that do not allow it are left out. Returns the number of certificates left
 * out.
 */
export function codeSigningRoot(root: TrustedRoot): { json: unknown; excluded: number } {
  const json = plain(root.json) as { certificateAuthorities?: { certChain: { certificates: unknown[] } }[] };
  let excluded = 0;
  root.certificateAuthorities.forEach((authority, i) => {
    const chain = json.certificateAuthorities?.[i]?.certChain;
    if (chain === undefined) throw new Error("trusted root certificate authorities do not match their parsed form");
    // chainDer is root first; the wire order is the issuing certificate first.
    const allowed = authority.chainDer.map((der) => {
      let cert: Certificate;
      try {
        cert = parseCertificate(der);
      } catch (err) {
        throw new Error(`parsing trusted root certificate authority: ${message(err)}`);
      }
      return allowsCodeSigning(cert);
    });
    if (allowed[0] === false) {
      excluded += chain.certificates.length;
      chain.certificates = [];
      return;
    }
    allowed.reverse();
    chain.certificates = chain.certificates.filter((_, j) => {
      if (allowed[j]) return true;
      excluded++;
      return false;
    });
  });
  return { json, excluded };
}

/** The plain-object form of a parsed value (trusted root or bundle), as the library reads it. */
function plain(json: JsonValue): unknown {
  return JSON.parse(new TextDecoder().decode(serialize(json))) as unknown;
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
