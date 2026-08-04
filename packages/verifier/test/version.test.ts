import { describe, expect, it } from 'vitest';
import packageMetadata from '../package.json';
import { VERIFIER_NAME, VERIFIER_VERSION } from '../src/version.js';

describe('verifier identity', () => {
  it('matches package metadata', () => {
    expect(VERIFIER_NAME).toBe(packageMetadata.name);
    expect(VERIFIER_VERSION).toBe(packageMetadata.version);
  });
});
