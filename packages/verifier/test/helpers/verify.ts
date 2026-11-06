/** Test-time plumbing from a full-verify vector's input to the verifier's arguments. */
import type { DangerousTestOnlyRoots } from "../../conformance/testing.js";
import { inputBytes, type ConformanceFixture } from "./conformance.js";

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/**
 * The injected anchors of a vector, laid out as the verifier takes them; an
 * absent anchor selects the embedded root. The AMD anchor is a pair, and a
 * vector that states only half of it is malformed rather than unanchored.
 */
export function rootsOf(fixture: ConformanceFixture): DangerousTestOnlyRoots {
  const roots: { amd?: Uint8Array; intel?: Uint8Array; sigstore?: Uint8Array } = {};
  const ark = fixture.input.amd_root_ca_pem ?? "";
  const ask = fixture.input.ask_pem ?? "";
  if ((ark === "") !== (ask === "")) throw new Error(`${fixture.id}: amd_root_ca_pem and ask_pem must be given together`);
  // KDS cert_chain order: ASK then ARK.
  if (ark !== "") roots.amd = utf8(`${ask.trim()}\n${ark.trim()}\n`);
  if (fixture.input.intel_sgx_root_pem) roots.intel = utf8(fixture.input.intel_sgx_root_pem);
  if (fixture.input.sigstore_trusted_root_json_b64) roots.sigstore = inputBytes(fixture, "sigstore_trusted_root_json_b64");
  return roots;
}

/** The vector's appraisal clock; 0 or absent means now. */
export function clockOf(fixture: ConformanceFixture): Date {
  const t = fixture.input.verification_time_unix;
  return t !== undefined && t !== 0 ? new Date(t * 1000) : new Date();
}
