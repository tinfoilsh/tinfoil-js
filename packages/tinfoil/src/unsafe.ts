/**
 * WARNING: THIS ENTRY IS INSECURE.
 *
 * The unverified EHBP client: bodies are sealed to whatever key the server
 * hands out, with no attestation, so it exists only to exercise the EHBP
 * protocol against a local development server. Anything that handles real
 * data uses the attested clients of the package's main entry.
 */
export { UnverifiedClient, UNVERIFIED_WARNING, type UnverifiedOptions } from "./internal/unsafe-client.js";
