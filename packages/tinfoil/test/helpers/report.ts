/**
 * Verification reports for test verifiers, which stand in for the verifier
 * with facts of their own: a report of a verification that every step
 * passed, holding those facts, with the methods that the client calls.
 * Only types are imported, so the helper loads in every runtime.
 */
import type { VerificationReport, VerifiedFacts } from "@tinfoilsh/verifier";

const LAYERS = ["envelope", "provenance", "quote", "policy"];

/** A report whose verified facts are `facts`, as a verifier returns it for a document that it accepted, or as a client names its `host`. */
export function verifiedReport(facts: VerifiedFacts | object, host?: string): VerificationReport {
  const steps = LAYERS.map((layer) => ({ layer, status: "passed", message: "" }));
  const metadata = { verifier: { name: "test", version: "0" }, verifiedAt: new Date(0), ...(host === undefined || host === "" ? {} : { host }) };
  const report = {
    steps,
    verifiedFacts: facts,
    metadata,
    failedStep: () => undefined,
    clone: () => ({ ...report }),
    withHost: (named: string) => verifiedReport(facts, named),
    // The report's JSON form, with the facts as they serialize themselves.
    toJSON: () => ({
      schema_version: 1,
      steps: steps.map(({ layer, status }) => ({ layer, status })),
      verified_facts: factsJSON(facts),
      metadata: { verified_at: metadata.verifiedAt.toISOString().replace(/\.000Z$/, "Z"), verifier: metadata.verifier, ...(host === undefined || host === "" ? {} : { host }) },
    }),
  };
  return report as unknown as VerificationReport;
}

/** The facts' JSON form: a real `VerifiedFacts` writes its own, and plain test facts are mapped to snake_case without the lifted channel keys. */
function factsJSON(facts: VerifiedFacts | object): unknown {
  if (typeof (facts as { toJSON?: unknown }).toJSON === "function") return (facts as VerifiedFacts).toJSON();
  const value = (v: unknown): unknown => {
    if (v instanceof Uint8Array) return Array.from(v, (b) => b.toString(16).padStart(2, "0")).join("");
    if (v instanceof Date) return v.toISOString().replace(/\.000Z$/, "Z");
    if (Array.isArray(v)) return v.map(value);
    if (v !== null && typeof v === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, x] of Object.entries(v)) {
        if (x === undefined || x === "" || k === "tlsPublicKeyFP" || k === "hpkePublicKey") continue;
        out[k.replace(/ID$/, "Id").replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`)] = value(x);
      }
      return out;
    }
    return v;
  };
  return value(facts);
}

/** The verified facts of the last attempt of `client`, if it passed: what the removed `current` getter returned. */
export function lastFacts(client: { lastVerificationAttempt(): { readonly report?: VerificationReport } | undefined }): VerifiedFacts | undefined {
  return client.lastVerificationAttempt()?.report?.verifiedFacts;
}
