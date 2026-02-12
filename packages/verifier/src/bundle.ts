/**
 * Bundle assembler — fetches all attestation components and packages them
 * into an AttestationBundle for verification.
 */

import { base64ToBytes, decompressGzip } from './attestation.js';
import { Report } from './sev/report.js';
import { tcbFromInt, bytesToHex } from './sev/utils.js';
import { FetchError, wrapOrThrow } from './errors.js';
import { PredicateType } from './types.js';
import type { AttestationBundle, AttestationDocument } from './types.js';

const MAX_RETRIES = 2;
const GITHUB_API_PROXY = 'https://api-github-proxy.tinfoil.sh';
const GITHUB_PROXY = 'https://github-proxy.tinfoil.sh';
const KDS_PROXY = 'https://kds-proxy.tinfoil.sh';

/** Retry on transient FetchError with exponential backoff (0.5s, 1s, 2s). */
async function withRetry<T>(fn: () => Promise<T>): Promise<T> {
  for (let i = 0; i <= MAX_RETRIES; i++) {
    try { return await fn(); }
    catch (e) { if (i === MAX_RETRIES || !(e instanceof FetchError)) throw e; }
    await new Promise(r => setTimeout(r, 500 * Math.pow(2, i)));
  }
  throw new Error('unreachable');
}

/**
 * Assemble a complete attestation bundle by fetching all components directly
 * from the enclave and public infrastructure.
 *
 * @throws FetchError on I/O failure (after retries)
 */
export async function assembleAttestationBundle(
  enclaveHost: string,
  configRepo: string,
): Promise<AttestationBundle> {
  const [attestationDoc, digest] = await Promise.all([
    withRetry(() => fetchAttestation(enclaveHost)),
    withRetry(() => fetchLatestDigest(configRepo)),
  ]);

  const sigstoreBundle = await withRetry(() => fetchSigstoreBundle(configRepo, digest));

  let vcek: string;
  try {
    const report = new Report(await decompressGzip(base64ToBytes(attestationDoc.body)));
    vcek = await withRetry(() => fetchVcek(report.productName, report.chipId, report.reportedTcb));
  } catch (err) {
    wrapOrThrow(err, FetchError, 'Failed to fetch VCEK certificate');
  }

  const enclaveCert = await withRetry(() => fetchEnclaveCertificate(enclaveHost));

  return {
    domain: enclaveHost,
    enclaveAttestationReport: attestationDoc,
    digest,
    sigstoreBundle,
    vcek,
    enclaveCert,
  };
}

// ---------------------------------------------------------------------------
// Individual fetch helpers
// ---------------------------------------------------------------------------

async function fetchAttestation(host: string): Promise<AttestationDocument> {
  const response = await fetch(`https://${host}/.well-known/tinfoil-attestation`);
  if (!response.ok) {
    throw new FetchError(`Failed to fetch attestation from ${host}: HTTP ${response.status}`);
  }
  const doc = await response.json();
  return { format: doc.format as PredicateType, body: doc.body };
}

async function fetchLatestDigest(repo: string): Promise<string> {
  const response = await fetch(`${GITHUB_API_PROXY}/repos/${repo}/releases/latest`);
  if (!response.ok) {
    throw new FetchError(`Failed to fetch latest release for ${repo}: HTTP ${response.status}`);
  }

  const { tag_name, body } = await response.json();

  // Try to extract digest from release body
  const match = /EIF hash: ([a-fA-F0-9]{64})/.exec(body)
    || /Digest: `([a-fA-F0-9]{64})`/.exec(body);
  if (match) return match[1];

  // Fallback: fetch from release asset
  const fallback = await fetch(`${GITHUB_PROXY}/${repo}/releases/download/${tag_name}/tinfoil.hash`);
  if (!fallback.ok) {
    throw new FetchError(`Failed to fetch digest for ${repo} tag ${tag_name}: HTTP ${fallback.status}`);
  }
  return (await fallback.text()).trim();
}

async function fetchSigstoreBundle(repo: string, digest: string): Promise<unknown> {
  const url = `${GITHUB_API_PROXY}/repos/${repo}/attestations/sha256:${digest}`;
  let data: { attestations: Array<{ bundle: unknown }> };
  try {
    const response = await fetch(url);
    if (!response.ok) {
      throw new FetchError(`Failed to fetch Sigstore bundle: HTTP ${response.status}`);
    }
    data = await response.json();
  } catch (e) {
    wrapOrThrow(e, FetchError, `Failed to fetch Sigstore bundle for ${repo}`);
  }
  if (!data.attestations?.[0]?.bundle) {
    throw new FetchError(`No attestation bundle found for ${repo} with digest ${digest}`);
  }
  return data.attestations[0].bundle;
}

async function fetchVcek(productName: string, chipId: Uint8Array, reportedTcb: bigint): Promise<string> {
  const tcb = tcbFromInt(reportedTcb);
  const chipIdHex = bytesToHex(chipId);
  const url = `${KDS_PROXY}/vcek/v1/${productName}/${chipIdHex}?blSPL=${tcb.blSpl}&teeSPL=${tcb.teeSpl}&snpSPL=${tcb.snpSpl}&ucodeSPL=${tcb.ucodeSpl}`;

  const response = await fetch(url);
  if (!response.ok) {
    throw new FetchError(`Failed to fetch VCEK certificate: HTTP ${response.status}`);
  }
  const der = new Uint8Array(await response.arrayBuffer());
  return btoa(String.fromCharCode(...der));
}

async function fetchEnclaveCertificate(host: string): Promise<string> {
  const response = await fetch(`https://${host}/.well-known/tinfoil-certificate`);
  if (!response.ok) {
    throw new FetchError(`Failed to fetch enclave certificate from ${host}: HTTP ${response.status}`);
  }
  return (await response.json()).certificate;
}
