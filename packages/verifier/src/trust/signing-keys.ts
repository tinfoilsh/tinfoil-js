/**
 * Tinfoil's ECDSA P-256 public key that signs config endorsements and
 * artifact-freshness approvals. Maintained by hand: rotating it is a
 * deliberate change, made in every SDK.
 */
export const PUBLIC_SIGNING_KEY_PEM =
  "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcadRPBdmNf1LPWYcY9AZ2Crrqxsy\nnqzLE7k3kahjPxIM42bgZbze0GnT/EmGqe1w6So5AhmXci8By8Azt8gAhw==\n-----END PUBLIC KEY-----";
