/**
 * Runs the shared tinfoil-conformance v3 fixtures through the adapter.
 *
 * Point TINFOIL_CONFORMANCE_FIXTURES at the suite's vectors/v3 directory (it
 * is searched recursively); the test is skipped when unset or missing. Fixtures whose
 * stage still hits a v3 placeholder report "unsupported" and are skipped.
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";
import { ExitCode, run, type Measurement } from "../conformance/adapter.js";

interface Fixture {
  id: string;
  stage: string;
  input: unknown;
  expected: {
    accepted: boolean;
    code?: string;
    tls_public_key_fp?: string;
    hpke_public_key?: string;
    code_digest?: string;
    code_measurement?: Measurement;
    enclave_measurement?: Measurement;
  };
}

function findFixtures(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) return findFixtures(p);
    return name.endsWith(".json") ? [p] : [];
  });
}

const dir = process.env.TINFOIL_CONFORMANCE_FIXTURES;
const files = dir && existsSync(dir) ? findFixtures(dir).sort() : [];

describe.skipIf(files.length === 0)("v3 conformance fixtures", () => {
  it.for(files.map((f) => [relative(dir!, f), f] as const))("%s", async ([, file], ctx) => {
    const f = JSON.parse(readFileSync(file, "utf8")) as Fixture;
    const { output, exitCode } = await run(f.stage, f.input);
    if (exitCode === ExitCode.Unsupported) ctx.skip();

    expect(output.accepted).toBe(f.expected.accepted);
    expect(exitCode).toBe(f.expected.accepted ? ExitCode.Accepted : f.expected.code === "MALFORMED_INPUT" ? ExitCode.Malformed : ExitCode.Rejected);
    if (!f.expected.accepted && f.expected.code) {
      expect(output.rejection?.code).toBe(f.expected.code);
    }
    if (f.expected.accepted) {
      const o = output.outputs ?? {};
      const e = f.expected;
      if (e.tls_public_key_fp) expect(o.tls_public_key_fp).toBe(e.tls_public_key_fp);
      if (e.hpke_public_key) expect(o.hpke_public_key).toBe(e.hpke_public_key);
      if (e.code_digest) expect(o.code_digest).toBe(e.code_digest);
      if (e.code_measurement) expect(o.code_measurement).toEqual(e.code_measurement);
      if (e.enclave_measurement) expect(o.enclave_measurement).toEqual(e.enclave_measurement);
    }
  });
});
