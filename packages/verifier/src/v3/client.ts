// v3 document verification flow (Go: verifier/client/verify.go):
// envelope check → reference-values authentication (code + platform, each
// with its freshness proof) → CPU quote verification. Every rejection throws
// VerificationError tagged with the failing layer.

import {
  check,
  CollateralSigstoreCodeV1Format,
  CollateralSigstorePlatformV1Format,
  CryptoMaterialIDHPKE,
  CryptoMaterialIDTLS,
  cryptoMaterialItems,
  freshnessCollateral,
  FreshnessCollateralIDCode,
  FreshnessCollateralIDPlatform,
  KeySPKIFPSHA256V1Format,
  KeyX25519HPKEV1Format,
  referenceValuesCollateral,
  type CryptoMaterialItem,
  type Document,
} from "./envelope.js";
import { VerificationError } from "./errors.js";
import type { Measurement } from "./measurement.js";
import { authenticateFreshness } from "./provenance/freshness.js";
import {
  authenticateCode,
  authenticatePlatformEndorsements,
  type Code,
  type PlatformEndorsements,
  type ProvenanceOpts,
} from "./provenance/provenance.js";
import { assembleAndValidate, quoteAuthenticate } from "./quote.js";

// VerifyOpts selects the trust anchors and pins the verification clock;
// defaults are the embedded production roots and the current time.
export interface VerifyOpts {
  sigstoreRootJSON?: Uint8Array;
  amdRootPEM?: string;
  intelRootPEM?: string;
  verificationTime?: Date;
}

// VerifiedDocumentV3 is what a verified v3 document proves. The operative
// output is cryptoMaterial — the endorsed keys a caller may bind a channel
// to (Go: client.VerifiedDocumentV3).
export interface VerifiedDocumentV3 {
  // codeDigest names the verified code artifact; codeMeasurement is the
  // expected measurement applied from it.
  codeDigest: string;
  codeTag: string;
  codeMeasurement: Measurement;
  // enclaveMeasurement carries the quote's authenticated registers, proven
  // to match the expectations.
  enclaveMeasurement: Measurement;
  // cryptoMaterial holds the endorsed key items (hash-bound into the quote).
  cryptoMaterial: CryptoMaterialItem[];
}

// tlsPublicKeyFP returns the endorsed TLS key fingerprint (the id=tls
// crypto_material entry) (Go: VerifiedDocumentV3.TLSPublicKeyFP).
export function tlsPublicKeyFP(v: VerifiedDocumentV3): string {
  return cryptoMaterialData(v, CryptoMaterialIDTLS, KeySPKIFPSHA256V1Format);
}

// hpkePublicKey returns the endorsed HPKE public key (the id=hpke
// crypto_material entry) (Go: VerifiedDocumentV3.HPKEPublicKey).
export function hpkePublicKey(v: VerifiedDocumentV3): string {
  return cryptoMaterialData(v, CryptoMaterialIDHPKE, KeyX25519HPKEV1Format);
}

function cryptoMaterialData(v: VerifiedDocumentV3, id: string, format: string): string {
  for (const item of v.cryptoMaterial) {
    if (item.id !== id) continue;
    if (item.format !== format) {
      throw new Error(`crypto_material item ${JSON.stringify(id)} has format ${JSON.stringify(item.format)}, want ${JSON.stringify(format)}`);
    }
    return item.data;
  }
  throw new Error(`document endorses no ${JSON.stringify(id)} crypto material`);
}

// verifyDocumentV3 verifies a v3 attestation document from its transmitted
// bytes (Go: client.VerifyDocumentV3):
//
//  1. Check the envelope: format, nonce equality, endorsed-section hash
//     recomputation, REPORT_DATA recomputation (no authentication).
//  2. Authenticate the reference values: the sigstore-code, sigstore-platform,
//     and sigstore-freshness entries against pinned signing identities.
//  3. Verify the CPU quote: authenticate against the pinned vendor roots,
//     assemble the complete policy from the reference values, validate in
//     one call.
//
// repo is the code repository the caller trusts (pins the sigstore-code
// signing identity); the repo named inside the document is not trusted.
// Channel binding (TLS fingerprint / HPKE key) is the caller's
// responsibility, using the returned endorsed crypto material.
export async function verifyDocumentV3(
  docBytes: Uint8Array,
  nonce: Uint8Array,
  repo: string,
  opts?: VerifyOpts,
): Promise<VerifiedDocumentV3> {
  const { doc, reportData } = await check(docBytes, nonce);

  const provOpts: ProvenanceOpts = { trustRootJSON: opts?.sigstoreRootJSON };
  const appraisal = opts?.verificationTime ?? new Date();
  const { code, endorsements } = await authenticateReferenceValues(doc, repo, appraisal, provOpts);

  const authenticated = await quoteAuthenticate(doc, {
    amdRootPEM: opts?.amdRootPEM,
    intelRootPEM: opts?.intelRootPEM,
    now: opts?.verificationTime,
  });
  assembleAndValidate(endorsements.artifact, code.measurement, code.shape, reportData, authenticated);

  return {
    codeDigest: code.digest,
    codeTag: code.tag,
    codeMeasurement: code.measurement,
    enclaveMeasurement: authenticated.measurement,
    cryptoMaterial: cryptoMaterialItems(doc),
  };
}

// authenticateReferenceValues authenticates the document's required code and
// platform Sigstore artifacts plus the matching freshness proof for each,
// both appraised at one time (Go: client.authenticateReferenceValues).
async function authenticateReferenceValues(
  doc: Document,
  repo: string,
  appraisal: Date,
  provOpts: ProvenanceOpts,
): Promise<{ code: Code; endorsements: PlatformEndorsements }> {
  const codeRef = referenceValuesCollateral(doc, CollateralSigstoreCodeV1Format);
  let code: Code;
  try {
    code = await authenticateCode(codeRef.sigstoreBundle, repo, codeRef.tag, codeRef.digest, provOpts);
  } catch (err) {
    throw wrap("verifying code measurement", err);
  }
  const codeFresh = freshnessCollateral(doc, FreshnessCollateralIDCode);
  try {
    await authenticateFreshness(codeFresh.sigstoreBundle, code, appraisal, provOpts);
  } catch (err) {
    throw wrap("verifying code freshness", err);
  }

  const platRef = referenceValuesCollateral(doc, CollateralSigstorePlatformV1Format);
  let endorsements: PlatformEndorsements;
  try {
    endorsements = await authenticatePlatformEndorsements(
      platRef.sigstoreBundle,
      platRef.repo,
      platRef.tag,
      platRef.digest,
      provOpts,
    );
  } catch (err) {
    throw wrap("verifying platform endorsements", err);
  }
  const platFresh = freshnessCollateral(doc, FreshnessCollateralIDPlatform);
  try {
    await authenticateFreshness(platFresh.sigstoreBundle, endorsements, appraisal, provOpts);
  } catch (err) {
    throw wrap("verifying platform freshness", err);
  }

  return { code, endorsements };
}

// wrap prefixes a step's context onto a rejection, preserving its layer.
function wrap(context: string, err: unknown): VerificationError {
  if (err instanceof VerificationError) {
    return new VerificationError(err.layer, `${context}: ${err.message}`);
  }
  return new VerificationError("PROVENANCE_REJECTED", `${context}: ${err instanceof Error ? err.message : String(err)}`);
}
