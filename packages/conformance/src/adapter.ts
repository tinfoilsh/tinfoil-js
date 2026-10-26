import { UsageError, VerificationError, type Verification, type ExpectedMeasurement, type ArtifactVerification } from '@tinfoilsh/verifier';
import { createVerifierForConformance, provenanceOptionsForConformance } from '../../verifier/src/client.js';
import { parseDocument, decodeDocumentForConformance } from '../../verifier/src/document.js';
import { fields, parseJSON, unbase64 } from '../../verifier/src/encoding.js';
import { authenticateCode, authenticatePlatform } from '../../verifier/src/provenance.js';
import { parseReference, PLATFORM_V1 } from '../../verifier/src/references.js';
import { authenticateQuote } from '../../verifier/src/quote/index.js';
import { der, pemCertificates } from '../../verifier/src/quote/crypto.js';
import { X509Certificate } from '@freedomofpress/sigstore-browser';
import type { SigstoreRoot } from '../../verifier/src/sigstore.js';
import { STAGES, reject, type Facts, type Input, type RejectionCode, type Verdict, type WireMeasurement } from './wire.js';

const inputFields = ['schema_version', 'document_b64', 'nonce_hex', 'repo', 'amd_root_ca_pem', 'ask_pem',
  'intel_sgx_root_pem', 'sigstore_trusted_root_json_b64', 'verification_time_unix'];
const layerCodes: Record<string, RejectionCode> = {
  envelope: 'ENVELOPE_REJECTED', provenance: 'PROVENANCE_REJECTED', quote: 'QUOTE_REJECTED', policy: 'POLICY_REJECTED',
};

export function measurement(value: ExpectedMeasurement): WireMeasurement {
  return value.type === 'sev-snp'
    ? { type: 'https://tinfoil.sh/predicate/sev-snp-guest/v2', registers: [value.launch ?? ''] }
    : { type: 'https://tinfoil.sh/predicate/tdx-guest/v2', registers: [value.mrtd, value.rtmr0, value.rtmr1, value.rtmr2, value.rtmr3].map(x => x ?? '') };
}

export function verificationFacts(value: Verification): Facts {
  const tls = value.tlsPublicKeyFingerprint(), hpke = value.hpkePublicKey();
  // The HTTP adapter profile requires both keys; generic verification does not.
  if (!tls || !hpke || !/^[0-9a-f]{64}$/.test(tls) || !/^[0-9a-f]{64}$/.test(hpke)) {
    throw new VerificationError('envelope', 'The conformance HTTP profile requires both endorsed channel keys');
  }
  const facts: Facts = { code_digest: value.codeDigest, code_measurement: measurement(value.codeMeasurement),
    enclave_measurement: measurement(value.enclaveMeasurement), tls_public_key_fp: tls, hpke_public_key: hpke };
  if (value.config) {
    const config = value.config;
    const artifact = (v: ArtifactVerification) => ({ source: v.source, repo: v.repo, tag: v.tag, digest: v.digest,
      name: v.name, commit: v.commit, approval_time_unix: v.approvalTime ? v.approvalTime.getTime() / 1000 : 0 });
    facts.config = { source: config.source, name: config.name, digest: config.digest, reference: config.reference,
      signing_key_hint: config.signingKeyHint, approval_time_unix: config.approvalTime ? config.approvalTime.getTime() / 1000 : 0 };
    if (value.runtime) facts.runtime = artifact(value.runtime);
    if (value.platform) facts.platform = artifact(value.platform);
    facts.freshness_expires_at_unix = value.freshnessExpiresAt ? value.freshnessExpiresAt.getTime() / 1000 : 0;
  }
  return facts;
}

export function errorVerdict(stage: string, error: unknown): Verdict {
  if (error instanceof UsageError) return reject(stage, 'MALFORMED_INPUT');
  if (error instanceof VerificationError && Object.prototype.hasOwnProperty.call(layerCodes, error.layer)) return reject(stage, layerCodes[error.layer]);
  return { exit: 1, output: { stage, accepted: false } };
}

function decodeInput(value: unknown) {
  const input = fields(value, inputFields, ['schema_version', 'document_b64']) as unknown as Input;
  if (input.schema_version !== '1') throw new Error('Unsupported input schema version');
  for (const key of inputFields.filter(x => x !== 'verification_time_unix')) {
    const value = (input as unknown as Record<string, unknown>)[key];
    if (value !== undefined && typeof value !== 'string') throw new Error(`Input ${key} must be a string`);
  }
  const document = unbase64(input.document_b64), nonceHex = input.nonce_hex ?? '';
  if (!/^(?:[0-9a-f]{2})*$/.test(nonceHex)) throw new Error('Invalid input nonce hex');
  const nonce = Uint8Array.from(nonceHex.match(/../g) ?? [], x => Number.parseInt(x, 16));
  const seconds = input.verification_time_unix ?? 0;
  if (!Number.isSafeInteger(seconds) || seconds < 0 || !Number.isFinite(new Date(seconds * 1000).getTime())) throw new Error('Invalid verification time');
  if (!!input.amd_root_ca_pem !== !!input.ask_pem) throw new Error('AMD root and ASK must be supplied together');
  let amdRootPem: string | undefined;
  if (input.amd_root_ca_pem && input.ask_pem) {
    if (pemCertificates(input.amd_root_ca_pem).length !== 1 || pemCertificates(input.ask_pem).length !== 1) throw new Error('Invalid AMD anchor pair');
    amdRootPem = input.ask_pem.trim() + '\n' + input.amd_root_ca_pem.trim() + '\n';
  }
  const intelRootPem = input.intel_sgx_root_pem || undefined;
  if (intelRootPem && pemCertificates(intelRootPem).length !== 1) throw new Error('Invalid Intel anchor');
  let sigstoreRoot: SigstoreRoot | undefined;
  if (input.sigstore_trusted_root_json_b64) {
    const root = parseJSON(unbase64(input.sigstore_trusted_root_json_b64));
    if (root.mediaType !== 'application/vnd.dev.sigstore.trustedroot+json;version=0.1') throw new Error('Invalid Sigstore root media type');
    for (const key of ['certificateAuthorities', 'ctlogs', 'tlogs', 'timestampAuthorities']) {
      if (!Array.isArray(root[key] ?? [])) throw new Error(`Invalid Sigstore root ${key}`);
    }
    for (const authority of [...(root.certificateAuthorities ?? []), ...(root.timestampAuthorities ?? [])]) {
      for (const cert of authority.certChain?.certificates ?? []) new X509Certificate(der(unbase64(cert.rawBytes)));
    }
    for (const log of [...(root.tlogs ?? []), ...(root.ctlogs ?? [])]) {
      if (!unbase64(log.publicKey?.rawBytes).length || unbase64(log.logId?.keyId).length !== 32) throw new Error('Invalid trusted log key');
    }
    sigstoreRoot = root;
  }
  return { input, document, nonce, trust: { amdRootPem, intelRootPem, sigstoreRoot }, now: seconds ? new Date(seconds * 1000) : new Date() };
}

export async function runAdapter(stage: string, value: unknown): Promise<Verdict> {
  if (!STAGES.includes(stage as typeof STAGES[number])) return { exit: 20, output: { stage, accepted: false } };
  let decoded: ReturnType<typeof decodeInput>;
  try { decoded = decodeInput(value); } catch (error) { return { ...reject(stage, 'MALFORMED_INPUT'), diagnostic: String(error) }; }
  const { input, document, nonce, trust, now } = decoded;
  if (stage === 'v3-check-envelope') {
    try { await parseDocument(document, nonce); return { exit: 0, output: { stage, accepted: true, outputs: {} } }; }
    catch { return reject(stage, 'ENVELOPE_REJECTED'); }
  }
  if (stage === 'verify-attestation-v3') {
    try {
      const verifier = createVerifierForConformance({}, trust);
      const verified = await verifier.verifyDocumentV3At(document, nonce, input.repo ?? '', now);
      return { exit: 0, output: { stage, accepted: true, outputs: verificationFacts(verified) } };
    } catch (error) { return errorVerdict(stage, error); }
  }
  let parsed: Awaited<ReturnType<typeof decodeDocumentForConformance>>;
  try { parsed = await decodeDocumentForConformance(document); } catch { return reject(stage, 'MALFORMED_INPUT'); }
  try {
    if (stage === 'v3-authenticate-quote') {
      const quote = await authenticateQuote(parsed.evidence, parsed.collateral.cpu, now, trust);
      return { exit: 0, output: { stage, accepted: true, outputs: { enclave_measurement: measurement(quote.measurement) } } };
    }
    const { root } = provenanceOptionsForConformance({}, trust);
    if (stage === 'v3-authenticate-provenance') {
      if (!parsed.collateral.code) throw new Error('Code collateral is absent');
      const code = await authenticateCode(parsed.collateral.code, parseReference(input.repo ?? ''), root);
      return { exit: 0, output: { stage, accepted: true, outputs: {
        code_digest: code.artifact.digest,
        code_measurement: { type: 'https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1', registers: [code.snp.launch, code.tdx.rtmr1, code.tdx.rtmr2] },
      } } };
    }
    if (!parsed.collateral.platform) throw new Error('Platform collateral is absent');
    await authenticatePlatform(parsed.collateral.platform, PLATFORM_V1, root);
    return { exit: 0, output: { stage, accepted: true, outputs: {} } };
  } catch (error) {
    if (error instanceof UsageError) return reject(stage, 'MALFORMED_INPUT');
    return reject(stage, stage === 'v3-authenticate-quote' ? 'QUOTE_REJECTED' : 'PROVENANCE_REJECTED');
  }
}

export function capabilities() {
  return { schema_version: '1', sdk: 'tinfoil-js', adapter_spec: '1.1.0', surface_spec: '1.0.0', v3: {
    supported: true, stages_supported: [...STAGES], synthetic_roots: { amd: true, intel: true, sigstore: true },
    freshness_enforced: true, live_verify: true, channel_binding: 'hpke',
  } };
}
