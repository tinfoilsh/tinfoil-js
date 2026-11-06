/**
 * The published type declarations, as `npm run build` emits them: only the
 * files the entry reaches, nothing marked internal, no test-only entry
 * point, no internal type named in a public signature, and the classes the
 * factories build with private constructors. The checks are shared with the
 * client package; this file supplies the verifier's data.
 */
import { fileURLToPath } from "node:url";
import { describeDeclarationPrune, describePublishedDeclarations } from "../../../test-support/declarations.js";

const dist = fileURLToPath(new URL("../dist/", import.meta.url));

describePublishedDeclarations({
  dist,
  entries: [`${dist}index.d.ts`],
  forbidden: [/@internal/, /dangerousTestOnly/i, /\bParts\b/, /ProvenanceClient/, /ConfigVerifier/, /FreshnessVerifier/, /InjectedRoots/, /buildVerifier/, /verificationOf/, /VerificationFields/, /DecodedDocument/, /BUILT_HERE/],
  privatelyConstructed: { Verification: "verification.d.ts", Verifier: "verifier.d.ts" },
});

describeDeclarationPrune();
