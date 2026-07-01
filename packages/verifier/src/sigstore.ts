import { PredicateType } from './types.js';
import type { AttestationMeasurement } from './types.js';
import type {
  TrustedRoot,
  X509Certificate,
  VerificationPolicy,
} from '@freedomofpress/sigstore-browser';
import sigstoreTrustedRoot from './sigstore-trusted-root.js';
import { AttestationError, FetchError, wrapOrThrow } from './errors.js';
import { base64ToBytes } from './attestation.js';
import { bytesToHex } from './dcode.js';
import type { HardwareMeasurement } from './types.js';

const GITHUB_PROXY = 'https://github-proxy.tinfoil.sh';
const HARDWARE_MEASUREMENTS_REPO = 'tinfoilsh/hardware-measurements';

/**
 * Tinfoil Sigstore policy — one field per SPEC §5 clause. All Tinfoil-specific
 * policy decisions are funneled through this struct. [`defaultSigstorePolicy`]
 * returns the canonical settings; the conformance binary builds alternative
 * policies to exercise specific clauses.
 */
export interface SigstorePolicy {
  /** Expected OIDC issuer extension value (exact match). SPEC §5.3. */
  oidcIssuer: string;
  /** Required prefix on the cert's GitHubWorkflowRef extension. SPEC §5.3. */
  workflowRefPrefix: string;
  /** Expected GitHubWorkflowRepository extension value (exact match). SPEC §5.3. */
  workflowRepository: string;
  /** Allow-list of predicate type URIs (SPEC §5.5). `null` means any. */
  predicateTypesAllowed: string[] | null;
  /** Allow-list of in-toto statement `_type` values. `null` means any. */
  inTotoStatementTypesAllowed: string[] | null;
  /** Required DSSE envelope `payload_type` (exact match). SPEC §5.4. */
  payloadType: string;
}

/**
 * Canonical Tinfoil policy: GitHub Actions OIDC, tag-triggered builds,
 * multiplatform predicate, in-toto v0.1/v1 statements.
 */
export function defaultSigstorePolicy(repo: string): SigstorePolicy {
  return {
    oidcIssuer: 'https://token.actions.githubusercontent.com',
    workflowRefPrefix: 'refs/tags/',
    workflowRepository: repo,
    predicateTypesAllowed: [PredicateType.SnpTdxMultiplatformV1],
    inTotoStatementTypesAllowed: [
      'https://in-toto.io/Statement/v0.1',
      'https://in-toto.io/Statement/v1',
    ],
    payloadType: 'application/vnd.in-toto+json',
  };
}

/**
 * Output of [`verifySigstoreBundleWithPolicy`]. Carries the extracted
 * measurement plus the fields surfaced to the conformance harness.
 */
export interface SigstoreVerification {
  measurement: AttestationMeasurement;
  predicateType: string;
  inTotoStatementType: string;
  subjectName: string;
  subjectDigestSha256Hex: string;
  certOidcIssuer: string;
  certWorkflowRepository: string;
  certWorkflowSignerUri: string;
  /** Hex of the Rekor logId.keyId (32 bytes). null if bundle has no tlog entries. */
  rekorLogIdHex: string | null;
  /** First tlog entry's integratedTime (seconds since epoch). null if no entries. */
  rekorIntegratedTimeUnix: number | null;
  /** Number of tlog entries in verificationMaterial. */
  tlogEntryCount: number;
  /** Number of SCTs embedded in the leaf cert. null if cert couldn't be parsed. */
  sctCount: number | null;
}

class GitHubWorkflowRefPrefix implements VerificationPolicy {
  constructor(private readonly prefix: string) {}

  verify(cert: X509Certificate): void {
    const ext = cert.extGitHubWorkflowRef;
    if (!ext) {
      throw new AttestationError(
        'WORKFLOW_REF_PREFIX_MISMATCH: Missing GitHub workflow reference extension'
      );
    }
    if (!ext.workflowRef.startsWith(this.prefix)) {
      throw new AttestationError(
        `WORKFLOW_REF_PREFIX_MISMATCH: cert workflow ref "${ext.workflowRef}" does not start with policy.workflowRefPrefix "${this.prefix}"`
      );
    }
  }
}

class WrappedOIDCIssuer implements VerificationPolicy {
  constructor(private readonly expected: string) {}

  verify(cert: X509Certificate): void {
    // Fulcio cert ext naming: V1 = 1.3.6.1.4.1.57264.1.1, V2 = .1.8.
    const v1 = cert.extFulcioIssuerV1?.issuer;
    const v2 = cert.extFulcioIssuerV2?.issuer;
    const got = v2 ?? v1;
    if (got !== this.expected) {
      throw new AttestationError(
        `OIDC_ISSUER_MISMATCH: cert OIDC issuer ${JSON.stringify(got ?? null)} does not equal policy.oidcIssuer ${JSON.stringify(this.expected)}`
      );
    }
  }
}

class WrappedGitHubWorkflowRepository implements VerificationPolicy {
  constructor(private readonly expected: string) {}

  verify(cert: X509Certificate): void {
    const got = cert.extGitHubWorkflowRepository?.workflowRepository;
    if (got !== this.expected) {
      throw new AttestationError(
        `WORKFLOW_REPOSITORY_MISMATCH: cert repository ${JSON.stringify(got ?? null)} does not equal policy.workflowRepository ${JSON.stringify(this.expected)}`
      );
    }
  }
}

/**
 * Verify a Sigstore bundle against an explicit policy and trust root.
 *
 * This is the mid-level entry that the SDK's standard verification path
 * ([`verifySigstoreBundle`]) and the conformance binary both call. It performs
 * no network I/O — bundle, expected digest, policy and trust root are all
 * caller-supplied.
 *
 * Verification follows SPEC §5:
 *   1. DSSE envelope signature + Fulcio chain + SCTs + Rekor inclusion
 *      (via @freedomofpress/sigstore-browser, using the supplied trust root).
 *   2. Certificate identity policy: OIDC issuer, repository, workflow-ref prefix.
 *   3. DSSE payload_type matches policy.payloadType (exact).
 *   4. in-toto statement._type ∈ policy.inTotoStatementTypesAllowed (if pinned).
 *   5. subject[0].digest.sha256 == expected digest (lowercase-normalized per SPEC §7.3).
 *   6. predicateType ∈ policy.predicateTypesAllowed (if pinned).
 *   7. Measurement extraction for the supported predicate types.
 */
export async function verifySigstoreBundleWithPolicy(
  bundleJson: unknown,
  expectedDigestSha256Hex: string,
  policy: SigstorePolicy,
  trustRoot: TrustedRoot
): Promise<SigstoreVerification> {
  try {
    const { SigstoreVerifier, AllOf } = await import(
      '@freedomofpress/sigstore-browser'
    );

    const verifier = new SigstoreVerifier();
    await verifier.loadSigstoreRoot(trustRoot);

    const bundle = bundleJson as any;

    // SPEC §5.2: only the v0.3 single-certificate bundle layout is accepted.
    // Reject the legacy v0.1/v0.2 layout, which conveys the signing cert under
    // verificationMaterial.x509CertificateChain (and may also carry CA certs —
    // a misuse vector the v0.3 single-certificate form avoids). Matches
    // tinfoil-go / -rs.
    if (bundle?.verificationMaterial?.x509CertificateChain) {
      throw new AttestationError(
        'BUNDLE_MALFORMED: legacy bundle format not supported: the ' +
          'x509CertificateChain layout requires the v0.3 single-certificate form'
      );
    }

    const certPolicy = new AllOf([
      new WrappedOIDCIssuer(policy.oidcIssuer),
      new WrappedGitHubWorkflowRepository(policy.workflowRepository),
      new GitHubWorkflowRefPrefix(policy.workflowRefPrefix),
    ]);

    // Verifies DSSE envelope signature, Fulcio chain, SCTs, Rekor inclusion,
    // and applies the certificate identity policy. Returns the verified payload.
    const { payloadType, payload: payloadBytes } = await verifier.verifyDsse(
      bundle,
      certPolicy
    );

    if (payloadType !== policy.payloadType) {
      throw new AttestationError(
        `PAYLOAD_TYPE_MISMATCH: DSSE payload_type ${JSON.stringify(payloadType)} does not equal policy.payloadType ${JSON.stringify(policy.payloadType)}`
      );
    }

    const payload = JSON.parse(new TextDecoder().decode(payloadBytes));

    // SPEC §5.4: the in-toto statement MUST contain only the recognized
    // top-level fields; reject unknown ones, matching tinfoil-go/-rs/-py.
    {
      const allowed = new Set(['_type', 'subject', 'predicateType', 'predicate']);
      const extra = Object.keys(payload).filter((k) => !allowed.has(k));
      if (extra.length > 0) {
        throw new AttestationError(
          `BUNDLE_MALFORMED: in-toto statement has unknown top-level field(s): ${extra.sort().join(', ')}`
        );
      }
    }

    const statementType: string | undefined = payload._type;
    if (
      policy.inTotoStatementTypesAllowed !== null &&
      (statementType === undefined ||
        !policy.inTotoStatementTypesAllowed.includes(statementType))
    ) {
      throw new AttestationError(
        `IN_TOTO_STATEMENT_TYPE_NOT_ALLOWED: in-toto statement _type ${JSON.stringify(statementType ?? null)} not in policy.inTotoStatementTypesAllowed`
      );
    }

    const subject = payload.subject?.[0];
    if (!subject || !subject.digest || typeof subject.digest.sha256 !== 'string') {
      throw new AttestationError(
        'SUBJECT_MISSING: in-toto statement has no subject[0].digest.sha256'
      );
    }
    // Lowercase-normalize per SPEC §7.3.
    if (
      expectedDigestSha256Hex.toLowerCase() !==
      subject.digest.sha256.toLowerCase()
    ) {
      throw new AttestationError(
        `SUBJECT_DIGEST_MISMATCH: bundle subject digest ${JSON.stringify(subject.digest.sha256)} does not equal expected ${JSON.stringify(expectedDigestSha256Hex)}`
      );
    }

    const predicateType: string | undefined = payload.predicateType;
    if (
      policy.predicateTypesAllowed !== null &&
      (predicateType === undefined ||
        !policy.predicateTypesAllowed.includes(predicateType))
    ) {
      throw new AttestationError(
        `PREDICATE_TYPE_NOT_ALLOWED: predicate type ${JSON.stringify(predicateType ?? null)} not in policy.predicateTypesAllowed`
      );
    }

    const predicateFields = payload.predicate;
    if (!predicateFields || typeof predicateFields !== 'object') {
      throw new AttestationError(
        'PREDICATE_MEASUREMENT_INVALID: payload is missing the predicate object'
      );
    }

    const measurement = extractMeasurement(
      predicateType as string,
      predicateFields
    );

    const cert = await extractCertificateInfo(bundle);
    const bundleObs = extractBundleObservables(bundle);

    return {
      measurement,
      predicateType: predicateType as string,
      inTotoStatementType: statementType ?? '',
      subjectName: typeof subject.name === 'string' ? subject.name : '',
      subjectDigestSha256Hex: subject.digest.sha256.toLowerCase(),
      certOidcIssuer: cert.oidcIssuer,
      certWorkflowRepository: cert.workflowRepository,
      certWorkflowSignerUri: cert.workflowSignerUri,
      rekorLogIdHex: bundleObs.rekorLogIdHex,
      rekorIntegratedTimeUnix: bundleObs.rekorIntegratedTimeUnix,
      tlogEntryCount: bundleObs.tlogEntryCount,
      sctCount: cert.sctCount,
    };
  } catch (e) {
    wrapOrThrow(e, AttestationError, 'Sigstore code bundle verification failed');
  }
}

/**
 * Standard SDK entry point. Thin wrapper around
 * [`verifySigstoreBundleWithPolicy`] using [`defaultSigstorePolicy`] and the
 * embedded Sigstore trusted root.
 *
 * @param bundleJson  The Sigstore bundle JSON object
 * @param digest      Expected SHA-256 hex digest of the release artifact
 * @param repo        GitHub repository (`owner/name`)
 */
export async function verifySigstoreBundle(
  bundleJson: unknown,
  digest: string,
  repo: string
): Promise<AttestationMeasurement> {
  const policy = defaultSigstorePolicy(repo);
  const result = await verifySigstoreBundleWithPolicy(
    bundleJson,
    digest,
    policy,
    sigstoreTrustedRoot as unknown as TrustedRoot
  );
  return result.measurement;
}

/** Extract all registers a Tinfoil predicate carries. Fixes the prior bug
 *  where SnpTdxMultiplatformV1 only emitted `[snp_measurement]` and dropped
 *  rtmr1/rtmr2 (recon finding). */
function extractMeasurement(
  predicateType: string,
  predicate: any
): AttestationMeasurement {
  if (predicateType === PredicateType.SnpTdxMultiplatformV1) {
    const snp = predicate.snp_measurement;
    if (typeof snp !== 'string') {
      throw new AttestationError(
        'PREDICATE_MEASUREMENT_INVALID: SnpTdxMultiplatformV1 missing snp_measurement'
      );
    }
    const rtmr1 = predicate.tdx_measurement?.rtmr1;
    const rtmr2 = predicate.tdx_measurement?.rtmr2;
    if (typeof rtmr1 !== 'string') {
      throw new AttestationError(
        'PREDICATE_MEASUREMENT_INVALID: SnpTdxMultiplatformV1 missing tdx_measurement.rtmr1'
      );
    }
    if (typeof rtmr2 !== 'string') {
      throw new AttestationError(
        'PREDICATE_MEASUREMENT_INVALID: SnpTdxMultiplatformV1 missing tdx_measurement.rtmr2'
      );
    }
    return {
      type: PredicateType.SnpTdxMultiplatformV1,
      registers: [snp, rtmr1, rtmr2],
    };
  }
  throw new AttestationError(
    `PREDICATE_MEASUREMENT_INVALID: predicate type ${JSON.stringify(predicateType)} extraction not implemented in tinfoil-js`
  );
}

/** Pull the cert identity fields out of the bundle for surfacing in the
 *  verification result, plus an SCT count derived from the SCT extension. */
async function extractCertificateInfo(bundle: any): Promise<{
  oidcIssuer: string;
  workflowRepository: string;
  workflowSignerUri: string;
  sctCount: number | null;
}> {
  const raw =
    bundle?.verificationMaterial?.certificate?.rawBytes ??
    bundle?.verificationMaterial?.x509CertificateChain?.certificates?.[0]
      ?.rawBytes;
  if (typeof raw !== 'string') {
    return {
      oidcIssuer: '',
      workflowRepository: '',
      workflowSignerUri: '',
      sctCount: null,
    };
  }
  try {
    const { X509Certificate } = await import('@freedomofpress/sigstore-browser');
    const der = base64ToBytes(raw);
    const cert = X509Certificate.parse(der);
    // OID precedence: V2 (.1.8) over V1 (.1.1). Mirrors the policy check in
    // WrappedOIDCIssuer above and the Rust verifier's extract_certificate_info.
    const oidcIssuer =
      cert.extFulcioIssuerV2?.issuer ?? cert.extFulcioIssuerV1?.issuer ?? '';
    const workflowRepository =
      cert.extGitHubWorkflowRepository?.workflowRepository ?? '';
    const workflowSignerUri = cert.extBuildSignerURI?.buildSignerURI ?? '';
    const sctCount = countSctsInCert(der);
    return { oidcIssuer, workflowRepository, workflowSignerUri, sctCount };
  } catch {
    return {
      oidcIssuer: '',
      workflowRepository: '',
      workflowSignerUri: '',
      sctCount: null,
    };
  }
}

/** Pure bundle parse: extract rekor log id, integrated time, and tlog count. */
function extractBundleObservables(bundle: any): {
  rekorLogIdHex: string | null;
  rekorIntegratedTimeUnix: number | null;
  tlogEntryCount: number;
} {
  const tlogs = bundle?.verificationMaterial?.tlogEntries;
  if (!Array.isArray(tlogs)) {
    return { rekorLogIdHex: null, rekorIntegratedTimeUnix: null, tlogEntryCount: 0 };
  }
  const first = tlogs[0];
  const logIdB64 = first?.logId?.keyId;
  const rekorLogIdHex =
    typeof logIdB64 === 'string' ? bytesToHex(base64ToBytes(logIdB64)) : null;
  const itRaw = first?.integratedTime;
  let rekorIntegratedTimeUnix: number | null = null;
  if (typeof itRaw === 'string') {
    const n = parseInt(itRaw, 10);
    if (!Number.isNaN(n)) rekorIntegratedTimeUnix = n;
  } else if (typeof itRaw === 'number') {
    rekorIntegratedTimeUnix = itRaw;
  }
  return { rekorLogIdHex, rekorIntegratedTimeUnix, tlogEntryCount: tlogs.length };
}

/** Hand-parse the SCT extension (OID 1.3.6.1.4.1.11129.2.4.2) to count entries.
 *  Walking DER is small enough to inline rather than pull a generic ASN.1 lib. */
function countSctsInCert(der: Uint8Array): number | null {
  // Outer cert is a SEQUENCE. The SCT extension's value is an OCTET STRING
  // wrapping another OCTET STRING that wraps a SerializedSCTList (2-byte total
  // length + per-SCT 2-byte length + body). We find the OID 06 0A 2B...
  const SCT_OID = new Uint8Array([
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02,
  ]);
  let i = 0;
  while (i + SCT_OID.length <= der.length) {
    let m = true;
    for (let j = 0; j < SCT_OID.length; j++) {
      if (der[i + j] !== SCT_OID[j]) {
        m = false;
        break;
      }
    }
    if (m) break;
    i++;
  }
  if (i + SCT_OID.length > der.length) return null;
  // After the OID, optionally a BOOLEAN critical flag (01 01 XX) then an
  // OCTET STRING (04 LL ...) wrapping the extension value, which itself is
  // an OCTET STRING wrapping SerializedSCTList.
  let p = i + SCT_OID.length;
  if (der[p] === 0x01 && der[p + 1] === 0x01) p += 3; // skip BOOLEAN critical
  if (der[p] !== 0x04) return null;
  const outer = parseDerLength(der, p + 1);
  if (!outer) return null;
  let inner = der.subarray(outer.offset, outer.offset + outer.length);
  if (inner[0] !== 0x04) return null;
  const innerLen = parseDerLength(inner, 1);
  if (!innerLen) return null;
  const list = inner.subarray(innerLen.offset, innerLen.offset + innerLen.length);
  if (list.length < 2) return null;
  const total = (list[0] << 8) | list[1];
  const body = list.subarray(2, 2 + Math.min(total, list.length - 2));
  let count = 0;
  let q = 0;
  while (q + 2 <= body.length) {
    const sctLen = (body[q] << 8) | body[q + 1];
    q += 2;
    if (q + sctLen > body.length) return null;
    q += sctLen;
    count++;
  }
  return count;
}

function parseDerLength(b: Uint8Array, at: number): { offset: number; length: number } | null {
  const first = b[at];
  if (first === undefined) return null;
  if (first < 0x80) return { offset: at + 1, length: first };
  const n = first & 0x7f;
  if (n === 0 || n > 4 || at + 1 + n > b.length) return null;
  let len = 0;
  for (let k = 0; k < n; k++) len = (len << 8) | b[at + 1 + k];
  return { offset: at + 1 + n, length: len };
}

async function verifyAndExtractPayload(
  bundleJson: unknown,
  digest: string,
  repo: string,
): Promise<{ predicateType: PredicateType; predicateFields: any }> {
  const {
    SigstoreVerifier,
    GITHUB_OIDC_ISSUER,
    AllOf,
    OIDCIssuer,
    GitHubWorkflowRepository,
  } = await import('@freedomofpress/sigstore-browser');

  const verifier = new SigstoreVerifier({
    ctlogThreshold: 1,
    tlogThreshold: 1,
  });
  await verifier.loadSigstoreRoot(sigstoreTrustedRoot);

  const policy = new AllOf([
    new OIDCIssuer(GITHUB_OIDC_ISSUER),
    new GitHubWorkflowRepository(repo),
    new GitHubWorkflowRefPrefix('refs/tags/'),
  ]);

  const { payloadType, payload: payloadBytes } = await verifier.verifyDsse(
    bundleJson as any,
    policy,
  );
  const payload = JSON.parse(new TextDecoder().decode(payloadBytes));

  if (payloadType !== 'application/vnd.in-toto+json') {
    throw new AttestationError(
      `Unsupported Sigstore payload type: "${payloadType}". Only in-toto statements (application/vnd.in-toto+json) are supported`,
    );
  }

  const bundleDigest = payload.subject?.[0]?.digest?.sha256;
  if (!bundleDigest) {
    throw new AttestationError('Invalid Sigstore bundle: Payload is missing subject digest');
  }
  if (digest.toLowerCase() !== String(bundleDigest).toLowerCase()) {
    throw new AttestationError(
      `Release digest mismatch: The release digest from GitHub (${digest}) does not match the digest in the sigstore bundle (${bundleDigest})`,
    );
  }

  const predicateType = payload.predicateType as PredicateType;
  const predicateFields = payload.predicate;

  if (!predicateFields) {
    throw new AttestationError('Invalid Sigstore bundle: Payload is missing the predicate field containing measurements');
  }

  return { predicateType, predicateFields };
}

/**
 * Fetches and verifies hardware measurements from the tinfoilsh/hardware-measurements repo.
 * Validates the Sigstore bundle and extracts MRTD/RTMR0 for each platform.
 */
export async function fetchHardwareMeasurements(): Promise<HardwareMeasurement[]> {
  try {
    const latestResp = await fetch(`${GITHUB_PROXY}/repos/${HARDWARE_MEASUREMENTS_REPO}/releases/latest`);
    if (!latestResp.ok) throw new FetchError(`HTTP ${latestResp.status}: failed to fetch latest hardware measurements release`);
    const { tag_name } = await latestResp.json();

    const hashResp = await fetch(`${GITHUB_PROXY}/${HARDWARE_MEASUREMENTS_REPO}/releases/download/${tag_name}/tinfoil.hash`);
    if (!hashResp.ok) throw new FetchError(`HTTP ${hashResp.status}: failed to fetch hardware measurements digest`);
    const digest = (await hashResp.text()).trim();

    const bundleResp = await fetch(`${GITHUB_PROXY}/repos/${HARDWARE_MEASUREMENTS_REPO}/attestations/sha256:${digest}`);
    if (!bundleResp.ok) throw new FetchError(`HTTP ${bundleResp.status}: failed to fetch hardware measurements attestation bundle`);
    const data = await bundleResp.json();
    if (!data.attestations?.[0]?.bundle) {
      throw new FetchError(`No Sigstore bundle for hardware measurements at digest ${digest}`);
    }

    const { predicateType, predicateFields } = await verifyAndExtractPayload(
      data.attestations[0].bundle,
      digest,
      HARDWARE_MEASUREMENTS_REPO,
    );

    if (predicateType !== PredicateType.HardwareMeasurementsV1) {
      throw new AttestationError(`Unexpected predicate type for hardware measurements: ${predicateType}`);
    }

    const measurements: HardwareMeasurement[] = [];
    for (const [key, value] of Object.entries(predicateFields)) {
      const fields = value as any;
      if (!fields.mrtd || !fields.rtmr0) {
        throw new AttestationError('Invalid hardware measurement: missing mrtd or rtmr0');
      }
      measurements.push({
        ID: `${key}@${digest}`,
        MRTD: fields.mrtd,
        RTMR0: fields.rtmr0,
      });
    }

    return measurements;
  } catch (e) {
    wrapOrThrow(e, AttestationError, 'Hardware measurements verification failed');
  }
}
