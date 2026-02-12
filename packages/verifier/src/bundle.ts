/**
 * Bundle assembler — fetches all attestation components and packages them
 * into an AttestationBundle for verification.
 */

import { base64ToBytes, decompressGzip } from './attestation.js';
import { Report } from './sev/report.js';
import { tcbFromInt, bytesToHex } from './sev/utils.js';
import { AttestationError, FetchError, wrapOrThrow } from './errors.js';
import { PredicateType } from './types.js';
import type { AttestationBundle, AttestationDocument } from './types.js';

const GITHUB_API = 'https://api-github-proxy.tinfoil.sh';
const GITHUB_DL = 'https://github-proxy.tinfoil.sh';
const KDS = 'https://kds-proxy.tinfoil.sh';

/**
 * Assemble a complete attestation bundle by fetching all components
 * directly from the enclave and public infrastructure.
 * Each network call is retried up to 2 times on transient failure.
 *
 * @throws FetchError on I/O failure (after retries)
 * @throws AttestationError if the attestation report cannot be parsed
 */
export async function assembleAttestationBundle(
  enclaveHost: string,
  configRepo: string,
): Promise<AttestationBundle> {

  // 1. Fetch independent resources in parallel
  const [attestation, digest, enclaveCert] = await Promise.all([
    withRetry(async (): Promise<AttestationDocument> => {
      const doc = await fetchJson(`https://${enclaveHost}/.well-known/tinfoil-attestation`);
      return { format: doc.format as PredicateType, body: doc.body };
    }),
    withRetry(async () => {
      const { tag_name } = await fetchJson(`${GITHUB_API}/repos/${configRepo}/releases/latest`);
      return (await fetchText(`${GITHUB_DL}/${configRepo}/releases/download/${tag_name}/tinfoil.hash`)).trim();
    }),
    withRetry(async () => {
      const data = await fetchJson(`https://${enclaveHost}/.well-known/tinfoil-certificate`);
      return data.certificate as string;
    }),
  ]);

  // 2. Fetch Sigstore bundle (needs digest)
  const sigstoreBundle = await withRetry(async () => {
    const data = await fetchJson(`${GITHUB_API}/repos/${configRepo}/attestations/sha256:${digest}`);
    if (!data.attestations?.[0]?.bundle) {
      throw new FetchError(`No Sigstore bundle for ${configRepo} at digest ${digest}`);
    }
    return data.attestations[0].bundle;
  });

  // 3. Parse attestation report
  let report: Report;
  try {
    report = new Report(await decompressGzip(base64ToBytes(attestation.body)));
  } catch (e) {
    wrapOrThrow(e, AttestationError, 'Failed to parse attestation report');
  }

  // 4. Fetch VCEK certificate from AMD KDS (needs parsed report)
  const vcek = await withRetry(async () => {
    const tcb = tcbFromInt(report.reportedTcb);
    const chip = bytesToHex(report.chipId);
    const der = await fetchBinary(
      `${KDS}/vcek/v1/${report.productName}/${chip}?blSPL=${tcb.blSpl}&teeSPL=${tcb.teeSpl}&snpSPL=${tcb.snpSpl}&ucodeSPL=${tcb.ucodeSpl}`,
    );
    let bin = '';
    for (let i = 0; i < der.length; i++) bin += String.fromCharCode(der[i]);
    return btoa(bin);
  });

  return {
    domain: enclaveHost,
    enclaveAttestationReport: attestation,
    digest,
    sigstoreBundle,
    vcek,
    enclaveCert,
  };
}

// ---------------------------------------------------------------------------
// Retry and typed fetch helpers
// ---------------------------------------------------------------------------

const MAX_RETRIES = 2;

/** Retry on transient FetchError with exponential backoff (0.5s, 1s, 2s). */
async function withRetry<T>(fn: () => Promise<T>): Promise<T> {
  for (let i = 0; i <= MAX_RETRIES; i++) {
    try { return await fn(); }
    catch (e) { if (i === MAX_RETRIES || !(e instanceof FetchError)) throw e; }
    await new Promise(r => setTimeout(r, 500 * Math.pow(2, i)));
  }
  throw new Error('unreachable');
}

/** Fetch a URL, throwing FetchError on non-OK or network failure. */
async function fetchOk(url: string): Promise<Response> {
  let response: Response;
  try {
    response = await fetch(url);
  } catch (e) {
    throw new FetchError(`Network error: ${url}`, { cause: e as Error });
  }
  if (!response.ok) {
    throw new FetchError(`HTTP ${response.status}: ${url}`);
  }
  return response;
}

async function fetchJson<T = any>(url: string): Promise<T> {
  try { return await (await fetchOk(url)).json(); }
  catch (e) { wrapOrThrow(e, FetchError, `Invalid response from ${url}`); }
}

async function fetchText(url: string): Promise<string> {
  try { return await (await fetchOk(url)).text(); }
  catch (e) { wrapOrThrow(e, FetchError, `Invalid response from ${url}`); }
}

async function fetchBinary(url: string): Promise<Uint8Array> {
  try { return new Uint8Array(await (await fetchOk(url)).arrayBuffer()); }
  catch (e) { wrapOrThrow(e, FetchError, `Invalid response from ${url}`); }
}
