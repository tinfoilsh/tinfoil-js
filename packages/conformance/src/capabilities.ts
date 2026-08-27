// Stage names plus the adapter's self-description; the suite reads
// capabilities to gate which fixtures this SDK runs
// (Go: verifier/conformance/capabilities.go).

export const StageVerify = "verify-attestation-v3"; // full envelope→provenance→freshness→quote→policy
export const StageCheckEnvelope = "v3-check-envelope"; // strict parse + nonce/hash/report-data binding
export const StageAuthenticateProvenance = "v3-authenticate-provenance"; // sigstore-code identity + measurement
export const StageAssemblePolicy = "v3-assemble-policy"; // sigstore-platform endorsements artifact
export const StageAuthenticateQuote = "v3-authenticate-quote"; // CPU quote signature chain to the vendor root

export function capabilities(): unknown {
  return {
    schema_version: "1",
    sdk: "tinfoil-js",
    v3: {
      supported: true,
      stages_supported: [
        StageVerify,
        StageCheckEnvelope,
        StageAuthenticateProvenance,
        StageAssemblePolicy,
        StageAuthenticateQuote,
      ],
      synthetic_roots: { amd: true, intel: true, sigstore: true },
      freshness_enforced: true,
      live_verify: true,
      channel_binding: "hpke",
    },
  };
}
