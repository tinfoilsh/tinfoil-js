/**
 * Verification reports for test verifiers, which stand in for the verifier
 * with facts of their own: a report of a verification that every step
 * passed, holding those facts, with the methods that the client calls.
 * Only types are imported, so the helper loads in every runtime.
 */
import type { VerificationReport, VerifiedFacts } from "@tinfoilsh/verifier";

const LAYERS = ["envelope", "provenance", "quote", "policy"];

/** A report whose verified facts are `facts`, as a verifier returns it for a document that it accepted. */
export function verifiedReport(facts: VerifiedFacts | object): VerificationReport {
  const steps = LAYERS.map((layer) => ({ layer, status: "passed", message: "" }));
  const metadata = { verifier: { name: "test", version: "0" }, verifiedAt: new Date(0) };
  const report = {
    steps,
    verifiedFacts: facts,
    metadata,
    failedStep: () => undefined,
    clone: () => ({ ...report }),
    toJSON: () => ({ steps, verifiedFacts: facts, metadata: { ...metadata, verifiedAt: metadata.verifiedAt.toISOString() } }),
  };
  return report as unknown as VerificationReport;
}

/** The verified facts of the last attempt of `client`, if it passed: what the removed `current` getter returned. */
export function lastFacts(client: { lastVerification(): { readonly report?: VerificationReport } | undefined }): VerifiedFacts | undefined {
  return client.lastVerification()?.report?.verifiedFacts;
}
