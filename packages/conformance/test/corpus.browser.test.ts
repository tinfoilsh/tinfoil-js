import { expect, it } from 'vitest';
// @ts-expect-error Vite loads the pinned, complete corpus at test-build time.
import fixtures from 'virtual:conformance-fixtures';
import { runAdapter } from '../src/adapter.js';
import type { Input } from '../src/wire.js';

// Corpus fixtures can intentionally omit expected facts. Their wire shape is
// still fixed by stage.
const classicFacts: Record<string, string[]> = {
  'v3-check-envelope': [],
  'v3-assemble-policy': [],
  'v3-authenticate-quote': ['enclave_measurement'],
  'v3-authenticate-provenance': ['code_digest', 'code_measurement'],
  'verify-attestation-v3': ['code_digest', 'code_measurement', 'enclave_measurement', 'tls_public_key_fp', 'hpke_public_key'],
};
interface Fixture { id: string; stage: string; input: Input; expected: Record<string, unknown> & { accepted: boolean; code?: string } }

it.each(fixtures as Fixture[])('$id', async fixture => {
  const result = await runAdapter(fixture.stage, fixture.input);
  expect(result.exit).toBe(fixture.expected.accepted ? 0 : fixture.expected.code === 'MALFORMED_INPUT' ? 30 : 10);
  if (fixture.expected.accepted) {
    const { accepted, ...outputs } = fixture.expected;
    expect(result.output).toEqual({ stage: fixture.stage, accepted, outputs: expect.objectContaining(outputs) });
    expect(Object.keys(result.output.outputs!).sort()).toEqual([...classicFacts[fixture.stage]].sort());
  } else {
    expect(result.output.outputs).toBeUndefined();
    expect(result.output).toEqual({ stage: fixture.stage, accepted: false, rejection: { code: fixture.expected.code } });
  }
});
