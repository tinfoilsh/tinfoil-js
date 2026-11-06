/**
 * Test-only ways into the verifier, for the conformance adapter and the
 * tests: a verifier under injected trust roots, and a document decoded
 * without its nonce binding. Nothing under `src/` imports this module and
 * the package does not publish it, so neither is reachable from the
 * package entry.
 */
import { decode, Document } from "../src/document/document.js";
import { buildVerifier, type InjectedRoots, type Verifier, type VerifierOptions } from "../src/verifier.js";

/** Trust roots that replace the embedded production anchors; an absent root keeps the embedded one. */
export type DangerousTestOnlyRoots = InjectedRoots;

/** Builds a verifier that trusts the injected roots instead of the embedded ones; otherwise as `Verifier.create`. */
export function dangerousTestOnlyVerifier(roots: DangerousTestOnlyRoots, options: VerifierOptions = {}): Promise<Verifier> {
  return buildVerifier(options, roots);
}

/** Decodes a document without binding it to a nonce, so one layer can be driven on its own. */
export async function dangerousTestOnlyDecode(docBytes: Uint8Array): Promise<Document> {
  return new Document(decode(docBytes));
}
