// Sigstore bundle wire shape and the format gates applied before any
// cryptography (Go: verifier/provenance/bundle_format.go plus the media-type
// validation sigstore-go performs in bundle.UnmarshalJSON).

import { utf8Decode } from "../bytes.js";
import { VerificationError } from "../errors.js";

export interface WireCertificate {
  rawBytes: string; // base64 DER
}

export interface WireTLogEntry {
  logIndex: string;
  logId: { keyId: string };
  kindVersion: { kind: string; version: string };
  integratedTime: string;
  inclusionPromise?: { signedEntryTimestamp: string };
  inclusionProof?: unknown;
  canonicalizedBody: string;
}

export interface WireTimestampVerificationData {
  rfc3161Timestamps?: { signedTimestamp: string }[];
}

export interface WireBundle {
  mediaType: string;
  verificationMaterial?: {
    certificate?: WireCertificate;
    x509CertificateChain?: { certificates?: WireCertificate[] };
    tlogEntries?: WireTLogEntry[];
    timestampVerificationData?: WireTimestampVerificationData;
  };
  dsseEnvelope?: {
    payload: string;
    payloadType: string;
    signatures?: { sig: string; keyid?: string }[];
  };
  messageSignature?: unknown;
}

function provErr(message: string): VerificationError {
  return new VerificationError("PROVENANCE_REJECTED", message);
}

// parseBundle decodes a Sigstore bundle JSON document and validates its media
// type (Go: bundle.UnmarshalJSON, which rejects unknown media types).
export function parseBundle(bundleJSON: Uint8Array): WireBundle {
  let b: unknown;
  try {
    b = JSON.parse(utf8Decode(bundleJSON));
  } catch (err) {
    throw provErr(`parsing bundle: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (b === null || typeof b !== "object" || Array.isArray(b)) {
    throw provErr("parsing bundle: not a JSON object");
  }
  const bundle = b as WireBundle;
  checkMediaType(bundle.mediaType);
  return bundle;
}

// checkMediaType mirrors sigstore-go's getBundleVersion: the legacy
// ";version=0.x" form or the "bundle.v0.x+json" form, versions 0.1–0.3.
function checkMediaType(mediaType: unknown): void {
  const base = "application/vnd.dev.sigstore.bundle";
  if (typeof mediaType !== "string") {
    throw provErr("parsing bundle: missing media type");
  }
  const legacy = ["0.1", "0.2", "0.3"].map((v) => `${base}+json;version=${v}`);
  if (legacy.includes(mediaType)) return;
  if (mediaType.startsWith(`${base}.v`) && mediaType.endsWith("+json")) {
    const version = mediaType.slice(`${base}.v`.length, -"+json".length);
    if (/^0\.[1-3]$/.test(version)) return;
  }
  throw provErr(`parsing bundle: unsupported media type ${JSON.stringify(mediaType)}`);
}

// rejectLegacyBundleFormat enforces SPEC §5.2: only the v0.3 single-certificate
// layout is accepted. The legacy v0.1/v0.2 layout conveys the signing
// certificate under verificationMaterial.x509CertificateChain, which may also
// carry intermediate or root CA certificates — a misuse vector the v0.3 form
// avoids.
export function rejectLegacyBundleFormat(b: WireBundle): void {
  if (b.verificationMaterial?.x509CertificateChain != null) {
    throw provErr(
      "legacy bundle format not supported: the x509CertificateChain layout requires the v0.3 single-certificate form",
    );
  }
}

// requireExactlyOneDSSESignature enforces the Sigstore bundle rule (SPEC §5.2)
// that a DSSE-envelope bundle carries exactly one signature, so both the
// empty (0) and duplicate (>1) cases fail with a clear, uniform reason.
export function requireExactlyOneDSSESignature(b: WireBundle): void {
  const env = b.dsseEnvelope;
  if (env == null) return; // not a DSSE-envelope bundle; nothing to check
  const n = env.signatures?.length ?? 0;
  if (n !== 1) {
    throw provErr(`DSSE envelope must have exactly one signature, got ${n}`);
  }
}
