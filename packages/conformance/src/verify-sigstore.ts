/**
 * verify-sigstore for tinfoil-js.
 *
 * Calls @tinfoilsh/verifier's `verifySigstoreBundleWithPolicy` with a
 * fixture-supplied trust root, policy, and expected digest. Maps library
 * errors to the SPEC-anchored rejection-code taxonomy.
 *
 * Verification time: the JS verifier path is hermetic on the system clock
 * because @freedomofpress/sigstore-browser scopes cert-chain validity to the
 * cert's NotBefore (extracted from the bundle), not `new Date()`. The
 * supplied `verification_time_unix` is therefore informational here — see
 * capabilities.known_quirks.
 */

import {
  verifySigstoreBundleWithPolicy,
  defaultSigstorePolicy,
  type SigstorePolicy,
} from '@tinfoilsh/verifier';

interface InputPolicy {
  oidc_issuer: string;
  workflow_ref_prefix: string;
  predicate_types_allowed?: string[] | null;
  in_toto_statement_types_allowed?: string[] | null;
  payload_type: string;
}

interface Input {
  schema_version: string;
  bundle_b64: string;
  expected_digest_sha256_hex: string;
  repo: string;
  policy: InputPolicy;
  trust_root_b64: string;
  verification_time_unix?: number;
}

interface VerifyResultBody {
  stage: 'verify-sigstore';
  accepted: boolean;
  outputs?: Record<string, unknown>;
  rejection?: { code: string; spec_ref?: string; message?: string };
}

export interface VerifyResult {
  exitCode: number;
  body: VerifyResultBody;
}

const EXIT_ACCEPT = 0;
const EXIT_REJECT = 10;
const EXIT_BAD_INPUT = 30;

export async function verifySigstore(raw: unknown): Promise<VerifyResult> {
  if (typeof raw !== 'object' || raw === null) {
    return reject('BUNDLE_MALFORMED', '5.2', 'input is not a JSON object', EXIT_BAD_INPUT);
  }
  const input = raw as Input;
  if (input.schema_version !== '1') {
    return reject('BUNDLE_MALFORMED', '5.2', 'input.schema_version != "1"', EXIT_BAD_INPUT);
  }

  let bundle: unknown;
  try {
    bundle = JSON.parse(
      Buffer.from(input.bundle_b64, 'base64').toString('utf-8'),
    );
  } catch (e) {
    return reject(
      'BUNDLE_MALFORMED',
      '5.2',
      `bundle_b64 not valid base64+JSON: ${(e as Error).message}`,
      EXIT_BAD_INPUT,
    );
  }

  let trustRoot: any;
  try {
    trustRoot = JSON.parse(
      Buffer.from(input.trust_root_b64, 'base64').toString('utf-8'),
    );
  } catch (e) {
    return reject(
      'TRUST_ROOT_INVALID',
      '5.1',
      `trust_root_b64 not valid base64+JSON: ${(e as Error).message}`,
      EXIT_BAD_INPUT,
    );
  }

  const policy: SigstorePolicy = {
    ...defaultSigstorePolicy(input.repo),
    oidcIssuer: input.policy.oidc_issuer,
    workflowRefPrefix: input.policy.workflow_ref_prefix,
    workflowRepository: input.repo,
    predicateTypesAllowed:
      input.policy.predicate_types_allowed === undefined
        ? defaultSigstorePolicy(input.repo).predicateTypesAllowed
        : input.policy.predicate_types_allowed,
    inTotoStatementTypesAllowed:
      input.policy.in_toto_statement_types_allowed === undefined
        ? defaultSigstorePolicy(input.repo).inTotoStatementTypesAllowed
        : input.policy.in_toto_statement_types_allowed,
    payloadType: input.policy.payload_type,
  };

  try {
    const v = await verifySigstoreBundleWithPolicy(
      bundle,
      input.expected_digest_sha256_hex,
      policy,
      trustRoot,
    );
    return {
      exitCode: EXIT_ACCEPT,
      body: {
        stage: 'verify-sigstore',
        accepted: true,
        outputs: {
          predicate_type: v.predicateType,
          in_toto_statement_type: v.inTotoStatementType,
          subject_name: v.subjectName,
          subject_digest_sha256_hex: v.subjectDigestSha256Hex,
          measurement: v.measurement,
          // cert_* fields left empty in v0.1 — known_quirks documents this.
          cert_oidc_issuer: v.certOidcIssuer,
          cert_workflow_repository: v.certWorkflowRepository,
          cert_workflow_signer_uri: v.certWorkflowSignerUri,
        },
      },
    };
  } catch (e) {
    const msg = (e as Error).message ?? String(e);
    const { code, spec_ref } = classifyError(msg);
    return reject(code, spec_ref, msg, EXIT_REJECT);
  }
}

function reject(
  code: string,
  spec_ref: string,
  message: string,
  exitCode: number,
): VerifyResult {
  return {
    exitCode,
    body: {
      stage: 'verify-sigstore',
      accepted: false,
      rejection: { code, spec_ref, message },
    },
  };
}

/**
 * Map a thrown AttestationError message to a (code, spec_ref).
 *
 * The verifier's policy-driven helpers lead with a stable rejection-code
 * prefix (e.g. "WORKFLOW_REF_PREFIX_MISMATCH:"). Messages from
 * @freedomofpress/sigstore-browser come through prefixed by
 * "Sigstore code bundle verification failed: " (the wrapOrThrow wrapper);
 * we coarse-match those by substring.
 */
function classifyError(raw: string): { code: string; spec_ref: string } {
  for (const [prefix, code, spec_ref] of PREFIX_MAP) {
    if (raw.includes(prefix)) return { code, spec_ref };
  }
  if (/(SCT|Signed Certificate Timestamp).*duplicate/i.test(raw))
    return { code: 'SCT_DUPLICATE_LOG', spec_ref: '5.2' };
  if (/SCT|Signed Certificate Timestamp/i.test(raw))
    return { code: 'SCT_INSUFFICIENT', spec_ref: '5.2' };
  if (/Rekor|tlog|inclusion proof|checkpoint/i.test(raw))
    return { code: 'REKOR_INCLUSION_INVALID', spec_ref: '5.2' };
  if (/Fulcio|CA|certificate chain|chain validation/i.test(raw))
    return { code: 'FULCIO_CHAIN_INVALID', spec_ref: '5.2' };
  if (/DSSE.*signature|signature.*invalid|verify signature/i.test(raw))
    return { code: 'DSSE_SIGNATURE_INVALID', spec_ref: '5.2' };
  if (/trust root|trusted root/i.test(raw))
    return { code: 'TRUST_ROOT_INVALID', spec_ref: '5.1' };
  return { code: 'BUNDLE_MALFORMED', spec_ref: '5.2' };
}

const PREFIX_MAP: ReadonlyArray<readonly [string, string, string]> = [
  ['OIDC_ISSUER_MISMATCH:', 'OIDC_ISSUER_MISMATCH', '5.3'],
  ['WORKFLOW_REPOSITORY_MISMATCH:', 'WORKFLOW_REPOSITORY_MISMATCH', '5.3'],
  ['WORKFLOW_REF_PREFIX_MISMATCH:', 'WORKFLOW_REF_PREFIX_MISMATCH', '5.3'],
  ['PAYLOAD_TYPE_MISMATCH:', 'PAYLOAD_TYPE_MISMATCH', '5.4'],
  ['IN_TOTO_STATEMENT_TYPE_NOT_ALLOWED:', 'IN_TOTO_STATEMENT_TYPE_NOT_ALLOWED', '5.4'],
  ['PREDICATE_TYPE_NOT_ALLOWED:', 'PREDICATE_TYPE_NOT_ALLOWED', '5.5'],
  ['SUBJECT_DIGEST_MISMATCH:', 'SUBJECT_DIGEST_MISMATCH', '5.4'],
  ['SUBJECT_MISSING:', 'SUBJECT_MISSING', '5.4'],
  ['PREDICATE_MEASUREMENT_INVALID:', 'PREDICATE_MEASUREMENT_INVALID', '5.5'],
  ['BUNDLE_MALFORMED:', 'BUNDLE_MALFORMED', '5.2'],
];
