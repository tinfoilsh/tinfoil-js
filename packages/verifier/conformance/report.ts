/**
 * The verification report in the conformance wire contract, for the
 * full-verify stage: the outcome of each step and, on a rejection, the
 * facts that the steps before it established. Step messages are each SDK's
 * own error text, so the wire carries only the layer and the status.
 */
import type { Measurement as V3Measurement } from "../src/measurement.js";
import type { VerificationReport } from "../src/report.js";
import type { Expected } from "../src/measurement.js";

/** A measurement as the wire lays it out: its predicate type and its registers in platform order. */
export interface WireMeasurement {
  type: string;
  registers: string[];
}

/** One step: a layer ("envelope", "provenance", "quote" or "policy") and a status ("passed", "failed", "skipped" or "not_run"). */
export interface ReportStep {
  layer: string;
  status: string;
}

/**
 * The accepted reference values. `code_measurement` is for the platform
 * that the document's evidence names, and `measurement`, the full
 * expectation, is present only once the policy step resolved it.
 */
export interface ReportExpectedFacts {
  code_digest?: string;
  code_measurement?: WireMeasurement;
  measurement?: WireMeasurement;
}

/**
 * What the document and its hardware claim. `cpu_measurement` is present
 * only once the quote step passed. The key fingerprints are unverified in a
 * rejection; `hpke_public_key_fp` is the lowercase-hex SHA-256 of the HPKE
 * key's bytes.
 */
export interface ReportMeasuredFacts {
  cpu_measurement?: WireMeasurement;
  tls_public_key_fp?: string;
  hpke_public_key_fp?: string;
}

/** What a rejected verification established: `expected` is absent unless provenance passed or was skipped, and `measured` unless the envelope passed. */
export interface ReportPartialFacts {
  expected?: ReportExpectedFacts;
  measured?: ReportMeasuredFacts;
}

/** A {@link VerificationReport} in the wire contract. */
export interface Report {
  steps: ReportStep[];
  partial_facts?: ReportPartialFacts;
}

/** The parts of an adapter output that {@link checkReport} reads. */
export interface ReportedOutput {
  stage: string;
  accepted: boolean;
  rejection?: { code: string };
  report?: Report;
}

/** Lays out `r` for the wire, with `measurementOf` and `expectedOf` laying out its registers. */
export function reportOf(r: VerificationReport, measurementOf: (m: V3Measurement) => WireMeasurement, expectedOf: (e: Expected) => WireMeasurement): Report {
  const out: Report = { steps: r.steps.map((s) => ({ layer: s.layer, status: s.status })) };
  const p = r.partialFacts;
  if (p !== undefined) {
    const partial: ReportPartialFacts = {};
    const e = p.expected;
    if (e !== undefined) {
      partial.expected = {
        ...(e.artifact.digest === "" ? {} : { code_digest: e.artifact.digest }),
        ...(e.codeMeasurement === undefined ? {} : { code_measurement: expectedOf(e.codeMeasurement) }),
        ...(e.measurement === undefined ? {} : { measurement: measurementOf(e.measurement) }),
      };
    }
    const m = p.measured;
    if (m !== undefined) {
      partial.measured = {
        ...(m.cpu === undefined ? {} : { cpu_measurement: measurementOf(m.cpu.measurement) }),
        ...(m.tlsPublicKeyFP === undefined ? {} : { tls_public_key_fp: m.tlsPublicKeyFP }),
        ...(m.hpkePublicKeyFP === undefined ? {} : { hpke_public_key_fp: m.hpkePublicKeyFP }),
      };
    }
    out.partial_facts = partial;
  }
  return out;
}

/** The layer of the step that failed, or undefined if none did. */
export function failedStep(r: Report | undefined): string | undefined {
  return r?.steps.find((s) => s.status === "failed")?.layer;
}

const LAYERS = ["envelope", "provenance", "quote", "policy"];

/** Each layer's rejection code. */
const REJECTION_LAYERS: Record<string, string> = {
  ENVELOPE_REJECTED: "envelope",
  PROVENANCE_REJECTED: "provenance",
  QUOTE_REJECTED: "quote",
  POLICY_REJECTED: "policy",
};

/**
 * Checks that a full-verify output's report agrees with its verdict and
 * keeps the report's rules: the four layers in order; on an accept, every
 * step passed or was skipped and there are no partial facts; on a
 * rejection, the failed step is the rejection code's layer, no step after
 * it ran, and each partial fact is present only once the step that
 * establishes it passed. A step before the failed one may be not_run, since
 * checks don't always run in layer order. Returns the first violation, or
 * undefined.
 */
export function checkReport(out: ReportedOutput): string | undefined {
  const r = out.report;
  if (out.accepted && out.rejection !== undefined) return `an accepted verdict carries rejection ${out.rejection.code}`;
  if (out.stage !== "verify-attestation-v3") return r === undefined ? undefined : `stage ${out.stage} carries a report`;
  if (r === undefined) {
    // The adapter's own channel-key rule rejects a document that the
    // verifier accepted, and a malformed input never ran.
    const code = out.rejection?.code;
    if (code === "ENVELOPE_REJECTED" || code === "MALFORMED_INPUT") return undefined;
    return `verdict ${JSON.stringify(out.rejection)} has no report`;
  }
  if (r.steps.length !== LAYERS.length) return `report has ${r.steps.length} steps, want ${LAYERS.length}`;
  let failedAt = -1;
  for (const [i, s] of r.steps.entries()) {
    if (s.layer !== LAYERS[i]) return `step ${i} is ${JSON.stringify(s.layer)}, want ${JSON.stringify(LAYERS[i])}`;
    if (failedAt >= 0) {
      if (s.status !== "not_run") return `step ${s.layer} after the failure is ${JSON.stringify(s.status)}, want not_run`;
    } else if (s.status === "failed") {
      failedAt = i;
    } else if (s.status !== "passed" && s.status !== "skipped" && s.status !== "not_run") {
      return `step ${s.layer} has unknown status ${JSON.stringify(s.status)}`;
    }
  }
  if (out.accepted) {
    const bad = r.steps.find((s) => s.status !== "passed" && s.status !== "skipped");
    if (bad !== undefined) return `an accepted report has step ${bad.layer} ${bad.status}`;
    if (r.partial_facts !== undefined) return "an accepted report has partial facts";
    return undefined;
  }
  if (out.rejection === undefined || failedAt < 0) return "a rejection's report has no failed step";
  if (REJECTION_LAYERS[out.rejection.code] !== LAYERS[failedAt]) return `failed step ${LAYERS[failedAt]} does not match rejection code ${out.rejection.code}`;
  const p = r.partial_facts;
  if (p === undefined) return "a rejection's report has no partial facts";
  const ran = (layer: string): boolean => {
    const status = r.steps.find((s) => s.layer === layer)?.status;
    return status === "passed" || status === "skipped";
  };
  if ((p.measured !== undefined) !== ran("envelope")) return `measured facts present=${p.measured !== undefined}, but the envelope step passed=${ran("envelope")}`;
  if ((p.expected !== undefined) !== ran("provenance")) return `expected facts present=${p.expected !== undefined}, but the provenance step passed=${ran("provenance")}`;
  if (p.measured !== undefined && (p.measured.cpu_measurement !== undefined) !== ran("quote")) {
    return `the CPU measurement is present=${p.measured.cpu_measurement !== undefined}, but the quote step passed=${ran("quote")}`;
  }
  if (p.expected?.measurement !== undefined && LAYERS[failedAt] !== "policy") return "the full expected measurement is present before the policy step ran";
  return undefined;
}
