import { TINFOIL_CONFIG } from "./config.js";
import type { AttestationBundle } from "./verifier.js";
import { FetchError } from "./verifier.js";

export interface FetchAttestationBundleOptions {
  atcBaseUrl?: string;
  enclaveURL?: string;
  configRepo?: string;
}

/**
 * Fetches a complete attestation bundle from ATC.
 *
 * When enclaveURL or configRepo are provided, issues a POST so ATC builds a
 * bundle for the specified enclave/repo. Otherwise issues a GET for the
 * default router behaviour.
 */
export async function fetchAttestationBundle(options: FetchAttestationBundleOptions = {}): Promise<AttestationBundle> {
  const baseUrl = options.atcBaseUrl ?? TINFOIL_CONFIG.ATC_BASE_URL;
  const url = `${baseUrl}/attestation`;

  const usePost = !!(options.enclaveURL || options.configRepo);

  const response = usePost
    ? await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enclaveUrl: options.enclaveURL,
          repo: options.configRepo,
        }),
      })
    : await fetch(url);

  if (!response.ok) {
    throw new FetchError(`Failed to fetch attestation bundle from ${baseUrl}: HTTP ${response.status} ${response.statusText}`);
  }

  const bundle = await response.json();

  return {
    domain: bundle.domain,
    enclaveAttestationReport: {
      format: bundle.enclaveAttestationReport.format,
      body: bundle.enclaveAttestationReport.body,
    },
    digest: bundle.digest,
    sigstoreBundle: bundle.sigstoreBundle,
    vcek: bundle.vcek,
    enclaveCert: bundle.enclaveCert,
  };
}

/**
 * Fetches the list of available routers and returns a randomly selected address.
 *
 * @param atcBaseUrl - Base URL for the attestation endpoint (defaults to TINFOIL_CONFIG.ATC_BASE_URL)
 * @returns A randomly selected router address
 * @throws Error if no routers are found or if the request fails
 */
export async function fetchRouter(atcBaseUrl: string = TINFOIL_CONFIG.ATC_BASE_URL): Promise<string> {
  const routersUrl = `${atcBaseUrl}/routers?platform=snp`;

  const response = await fetch(routersUrl);

  if (!response.ok) {
    throw new FetchError(`Failed to fetch router list from ${atcBaseUrl}: HTTP ${response.status} ${response.statusText}`);
  }

  const routers: string[] = await response.json();

  if (!Array.isArray(routers) || routers.length === 0) {
    throw new FetchError("No available routers found in the response");
  }

  return routers[Math.floor(Math.random() * routers.length)];
}
