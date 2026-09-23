// Attestation transport helpers (Go: envelope.Fetch, envelope.RandomNonce).
// Engine-neutral: global fetch + WebCrypto only.

import { encodeHex } from "./bytes.js";
import { NonceSize } from "./envelope.js";

const attestationEndpoint = "/.well-known/tinfoil-attestation";

// fetchAttestation retrieves a v3 attestation document from an enclave host,
// binding it to the caller's nonce; host may already carry a port. The bytes
// are untrusted until verifyDocumentV3 accepts them.
export async function fetchAttestation(host: string, nonce: Uint8Array): Promise<Uint8Array> {
  if (nonce.length !== NonceSize) {
    throw new Error(`nonce must be ${NonceSize} bytes, got ${nonce.length}`);
  }
  const resp = await fetch(`https://${host}${attestationEndpoint}?nonce=${encodeHex(nonce)}`);
  if (!resp.ok) {
    throw new Error(`fetching attestation from ${host}: HTTP ${resp.status}`);
  }
  return new Uint8Array(await resp.arrayBuffer());
}

// randomNonce returns a fresh NonceSize-byte verifier nonce.
export function randomNonce(): Uint8Array {
  const nonce = new Uint8Array(NonceSize);
  globalThis.crypto.getRandomValues(nonce);
  return nonce;
}
