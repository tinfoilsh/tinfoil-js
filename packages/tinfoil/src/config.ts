/**
 * Configuration constants for the Tinfoil Node SDK
 */
export const TINFOIL_CONFIG = {
  /**
   * Base URL for the ATC (Air Traffic Control) service
   */
  ATC_BASE_URL: "https://atc.tinfoil.sh",

  /**
   * The GitHub repository for the router code attestation
   */
  DEFAULT_ROUTER_REPO: "tinfoilsh/confidential-model-router",
} as const;
