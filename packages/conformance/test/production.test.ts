import { expect, it } from 'vitest';
import { Verifier } from '@tinfoilsh/verifier';
import { verificationFacts } from '../src/adapter.js';
import snp from '../../verifier/test/fixtures/production-v3.json';
import tdx from '../../verifier/test/fixtures/production-tdx-v3.json';
import turin from '../../verifier/test/fixtures/production-turin-v3.json';
import expected from './fixtures/production-facts.json';

const captures = [
  { name: 'snp', capture: snp, facts: expected.facts.snp },
  { name: 'tdx', capture: tdx, facts: expected.facts.tdx },
  { name: 'turin', capture: turin, facts: expected.facts.turin },
];

it.each(captures)('verifies the production $name archive with embedded roots and Go-identical facts', async ({ capture, facts }) => {
  const document = Uint8Array.from(atob(capture.documentBase64), character => character.charCodeAt(0));
  const nonce = Uint8Array.from(capture.nonceHex.match(/../g)!, hex => Number.parseInt(hex, 16));
  const at = new Date(capture.capturedAt);
  const result = await new Verifier().verifyDocumentV3At(document, nonce, capture.identity, at);
  expect(verificationFacts(result)).toEqual(facts);
  expect(result.metadata.verifiedAt.getTime()).toBe(at.getTime());
  expect(result.freshnessExpiresAt!.getTime()).toBeGreaterThan(at.getTime());
});
