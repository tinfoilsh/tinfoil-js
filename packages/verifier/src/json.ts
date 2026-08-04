import type { VerificationDocument } from './types.js';

export function cloneVerificationDocument(document: VerificationDocument): VerificationDocument {
  return structuredClone(document);
}
