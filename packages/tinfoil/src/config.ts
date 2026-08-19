/**
 * Configuration constants for the Tinfoil Node SDK
 */
export const TINFOIL_CONFIG = {
  /**
   * Base URL for the attestation endpoint
   */
  ATC_BASE_URL: "https://atc.tinfoil.sh",

  /**
   * Stable legacy inference enclave origin. This endpoint does not forward
   * requests to an independently selected router.
   */
  INFERENCE_ORIGIN: "https://inference.tinfoil.sh",

  /**
   * The GitHub repository for the router code attestation
   */
  DEFAULT_ROUTER_REPO: "tinfoilsh/confidential-model-router",
} as const;
