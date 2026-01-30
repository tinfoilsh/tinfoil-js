import { TINFOIL_CONFIG } from "./config.js";
import type { AttestationBundle } from "@tinfoilsh/verifier";

/**
 * Fetches a complete attestation bundle.
 * The bundle contains all material needed for verification without additional network calls.
 *
 * @param atcBaseUrl - Base URL for the attestation endpoint (defaults to TINFOIL_CONFIG.ATC_BASE_URL)
 * @returns The complete attestation bundle
 * @throws Error if the request fails
 */
export async function fetchAttestationBundle(atcBaseUrl: string = TINFOIL_CONFIG.ATC_BASE_URL): Promise<AttestationBundle> {
  const url = `${atcBaseUrl}/attestation`;
  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(`Failed to fetch attestation bundle: ${response.status} ${response.statusText}`);
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
    throw new Error(`Failed to fetch routers: ${response.status} ${response.statusText}`);
  }

  const routers: string[] = await response.json();

  if (!Array.isArray(routers) || routers.length === 0) {
    throw new Error("No routers found in the response");
  }

  return routers[Math.floor(Math.random() * routers.length)];
}
