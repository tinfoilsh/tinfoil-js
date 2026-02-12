/**
 * Bundle assembler — fetches all attestation components and packages them
 * into an AttestationBundle for verification.
 */

import { fetchAttestation, base64ToBytes, decompressGzip } from './attestation.js';
import { fetchLatestDigest, fetchGithubAttestationBundle } from './github.js';
import { Report } from './sev/report.js';
import { buildVCEKUrl, fetchVCEK } from './sev/cert-chain.js';
import { FetchError, wrapOrThrow } from './errors.js';
import type { AttestationBundle } from './types.js';

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
  // Fetch attestation doc + digest in parallel
  const [attestationDoc, digest] = await Promise.all([
    withRetry(() => fetchAttestation(enclaveHost)),
    withRetry(() => fetchLatestDigest(configRepo)),
  ]);

  // Fetch sigstore bundle (depends on digest)
  const sigstoreBundle = await withRetry(() =>
    fetchGithubAttestationBundle(configRepo, digest)
  );

  // Parse attestation report to build VCEK URL, then fetch VCEK
  let vcek: string;
  try {
    const report = new Report(await decompressGzip(base64ToBytes(attestationDoc.body)));
    const vcekDer = await withRetry(() =>
      fetchVCEK(buildVCEKUrl(report.productName, report.chipId, report.reportedTcb))
    );
    vcek = btoa(String.fromCharCode(...vcekDer));
  } catch (err) {
    wrapOrThrow(err, FetchError, 'Failed to fetch VCEK certificate');
  }

  // Fetch enclave TLS certificate
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

async function fetchEnclaveCertificate(host: string): Promise<string> {
  const response = await fetch(`https://${host}/.well-known/tinfoil-certificate`);
  if (!response.ok) {
    throw new FetchError(`Failed to fetch enclave certificate from ${host}: HTTP ${response.status}`);
  }
  return (await response.json()).certificate;
}
