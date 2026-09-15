// Full shared v3 conformance suite executed in a real browser.
//
// Fixtures are synced from tinfoil-conformance/vectors/v3 into
// test/fixtures/v3-vectors (gitignored) by scripts/sync-v3-fixtures.mjs; run
// via `npm run test:browser:conformance -w packages/verifier`. The assertion
// contract mirrors tinfoil-conformance/tools/run_adapter.py exactly.
import { afterAll, describe, expect, it } from "vitest";

import {
  ExitAccepted,
  ExitMalformed,
  ExitRejected,
  ExitUnsupported,
  runStage,
  type Input,
  type Output,
} from "../../conformance/src/run.js";

// Declared accept facts checked when present (run_adapter.py FACTS).
const FACTS = ["code_digest", "code_measurement", "enclave_measurement", "tls_public_key_fp", "hpke_public_key"] as const;

interface Fixture {
  id?: string;
  stage: string;
  input: Input;
  expected: { accepted: boolean; code?: string } & Partial<Record<(typeof FACTS)[number], unknown>>;
}

const modules = import.meta.glob<{ default: Fixture }>("./fixtures/v3-vectors/*/*.json");

// Group fixture loaders by suite directory, sorted like run_adapter.py.
const byDir = new Map<string, { name: string; load: () => Promise<{ default: Fixture }> }[]>();
for (const path of Object.keys(modules).sort()) {
  const parts = path.split("/"); // ./fixtures/v3-vectors/<dir>/<file>.json
  const dir = parts[parts.length - 2];
  const list = byDir.get(dir) ?? [];
  list.push({ name: parts[parts.length - 1], load: modules[path] });
  byDir.set(dir, list);
}

const counts = new Map<string, { pass: number; fail: number; skip: number; total: number }>();
for (const [dir, list] of byDir) counts.set(dir, { pass: 0, fail: 0, skip: 0, total: list.length });

// assertVerdict applies run_adapter.py's contract to one fixture result.
function assertVerdict(exp: Fixture["expected"], output: Output, exitCode: number): void {
  if (exp.accepted) {
    expect(exitCode, `rejected (${JSON.stringify(output.rejection)})`).toBe(ExitAccepted);
    expect(output.accepted).toBe(true);
    const got = output.outputs ?? {};
    for (const k of FACTS) {
      if (k in exp) expect(got[k], k).toEqual(exp[k]);
    }
  } else {
    expect([ExitRejected, ExitMalformed], `accepted, want reject ${exp.code}`).toContain(exitCode);
    expect(output.accepted).toBe(false);
    if (exp.code) expect(output.rejection?.code).toBe(exp.code);
  }
}

it("runs in a real browser with synced fixtures", () => {
  // Guard against silently falling back to a Node environment.
  expect(typeof window).toBe("object");
  expect(typeof document).toBe("object");
  expect(navigator.userAgent).toMatch(/Chrome|Chromium|HeadlessChrome/);
  expect(
    byDir.size,
    "no fixtures found — run `node scripts/sync-v3-fixtures.mjs` (see src/v3/PORTING.md)",
  ).toBeGreaterThan(0);
});

for (const [dir, list] of byDir) {
  describe(dir, () => {
    for (const { name, load } of list) {
      it(name, async (ctx) => {
        const fixture = (await load()).default;
        const { output, exitCode } = await runStage(fixture.stage, fixture.input);
        const rec = counts.get(dir)!;
        if (exitCode === ExitUnsupported) {
          rec.skip++;
          ctx.skip();
        }
        try {
          assertVerdict(fixture.expected, output, exitCode);
          rec.pass++;
        } catch (err) {
          rec.fail++;
          throw err;
        }
      });
    }
  });
}

afterAll(() => {
  let pass = 0;
  let fail = 0;
  let skip = 0;
  let total = 0;
  const lines: string[] = [];
  for (const [dir, c] of counts) {
    pass += c.pass;
    fail += c.fail;
    skip += c.skip;
    total += c.total;
    lines.push(
      `${dir.padEnd(18)} ${c.pass}/${c.total} pass` +
        (c.skip ? `, ${c.skip} skip` : "") +
        (c.fail ? `, ${c.fail} FAIL` : ""),
    );
  }
  lines.push(`TOTAL ${pass}/${total} pass, ${skip} skip, ${fail} fail`);
  console.log(`\nv3 conformance (browser)\n${lines.join("\n")}`);
});
