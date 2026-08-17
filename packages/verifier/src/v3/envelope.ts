// The v3 attestation document wire format and its strict parsing and
// challenge verification, a 1:1 port of Go verifier/envelope/envelope.go.
// Verifying the envelope authenticates nothing by itself: the CPU quote must
// prove the hardware bound the recomputed REPORT_DATA before any part of the
// document is trusted.
//
// The document is flat: a challenge, CPU evidence, two endorsed sections
// (crypto_material, device_evidence), and an array of collateral entries.
// The endorsed sections are hash-bound into the CPU quote's REPORT_DATA:
//
//   crypto_material_hash = SHA-256(base64-decoded crypto_material JSON bytes)
//   device_evidence_hash = SHA-256(base64-decoded device_evidence JSON bytes)
//   REPORT_DATA[0:32]    = SHA-256(ReportDataV1Algorithm || nonce || crypto_material_hash || device_evidence_hash)
//   REPORT_DATA[32:64]   = zeros
//
// Endorsed-section hashes are computed over the exact base64-decoded section
// bytes; verifiers must never re-serialize them.

import {
  decodeCanonicalBase64,
  decodeLowerHex,
  encodeHex,
  isLowerHex,
  sha256,
  utf8Encode,
} from "./bytes.js";
import { CollateralNotFoundError, VerificationError } from "./errors.js";
import {
  arrayOf,
  field,
  mapOf,
  raw,
  str,
  structOf,
  unmarshal,
  type Schema,
} from "./strictjson.js";

// Format registry (v3).

// AttestationV3Format identifies the v3 attestation document.
export const AttestationV3Format = "https://tinfoil.sh/predicate/attestation/v3";

// ReportDataV1Algorithm identifies the REPORT_DATA derivation above.
export const ReportDataV1Algorithm = "https://tinfoil.sh/report-data/v1";

// CryptoMaterialV1Format is the crypto_material section envelope.
export const CryptoMaterialV1Format = "https://tinfoil.sh/crypto-material/v1";
// DeviceEvidenceV1Format is the device_evidence section envelope.
export const DeviceEvidenceV1Format = "https://tinfoil.sh/device-evidence/v1";

// SEVSNPReportV1Format is a raw 1184-byte SEV-SNP report, base64.
export const SEVSNPReportV1Format = "https://tinfoil.sh/format/sev-snp-report/v1";
// TDXQuoteV1Format is a raw TDX Quote v4, base64.
export const TDXQuoteV1Format = "https://tinfoil.sh/format/tdx-quote/v1";
// NvidiaGPUEvidenceV1Format is an NVIDIA GPU evidence payload.
export const NvidiaGPUEvidenceV1Format = "https://tinfoil.sh/format/nvidia-gpu-evidence/v1";

// KeySPKIFPSHA256V1Format is a 32-byte SHA-256 of the DER-encoded
// SubjectPublicKeyInfo (RFC 5280), the standard pinning computation.
export const KeySPKIFPSHA256V1Format = "https://tinfoil.sh/key/spki-fp-sha256/v1";
// KeyX25519HPKEV1Format is a raw 32-byte X25519 public key (RFC 7748)
// used for HPKE (RFC 9180).
export const KeyX25519HPKEV1Format = "https://tinfoil.sh/key/x25519-hpke/v1";

// CollateralAMDVCEKV1Format carries {vcek_der_base64, cert_chain_pem}.
export const CollateralAMDVCEKV1Format = "https://tinfoil.sh/collateral/amd-vcek/v1";
// CollateralAMDCRLV1Format carries {crl_der_base64}: the AMD KDS CRL for the
// product line, enabling offline VCEK revocation checking.
export const CollateralAMDCRLV1Format = "https://tinfoil.sh/collateral/amd-crl/v1";
// CollateralIntelPCSV1Format carries captured Intel PCS responses
// (TCB info, QE identity, CRLs) for offline TDX quote verification.
export const CollateralIntelPCSV1Format = "https://tinfoil.sh/collateral/intel-pcs/v1";
// CollateralNvidiaGPUV1Format carries NVIDIA cert chains / RIM material.
export const CollateralNvidiaGPUV1Format = "https://tinfoil.sh/collateral/nvidia-gpu/v1";
// CollateralSigstoreCodeV1Format carries the code-provenance Sigstore bundle
// {repo, tag, digest, sigstore_bundle}.
export const CollateralSigstoreCodeV1Format = "https://tinfoil.sh/collateral/sigstore-code/v1";
// CollateralSigstorePlatformV1Format carries the platform-endorsements
// Sigstore bundle {repo, tag, digest, sigstore_bundle}.
export const CollateralSigstorePlatformV1Format = "https://tinfoil.sh/collateral/sigstore-platform/v1";
// CollateralSigstoreFreshnessV1Format carries a freshness witness for a
// Sigstore reference-values artifact.
export const CollateralSigstoreFreshnessV1Format = "https://tinfoil.sh/collateral/sigstore-freshness/v1";

// Collateral roles (RATS, RFC 9334).

// RoleEndorsement labels hardware-vendor material used to cryptographically
// verify evidence (e.g. AMD VCEK chains, Intel PCS).
export const RoleEndorsement = "endorsement";
// RoleReferenceValues labels Tinfoil-signed expectations used to appraise
// verified evidence.
export const RoleReferenceValues = "reference-values";

// Conventional identifiers.

// CryptoMaterialIDTLS is the conventional id of the TLS key fingerprint.
export const CryptoMaterialIDTLS = "tls";
// CryptoMaterialIDHPKE is the conventional id of the HPKE public key.
export const CryptoMaterialIDHPKE = "hpke";
// SubjectCPU is the reserved collateral subject id for the CPU quote.
export const SubjectCPU = "cpu";
// Freshness collateral IDs associate each freshness proof with the Sigstore
// reference-values entry it refreshes.
export const FreshnessCollateralIDCode = "code-freshness";
export const FreshnessCollateralIDPlatform = "platform-freshness";

// NonceSize is the required challenge nonce size in bytes.
export const NonceSize = 32;

// Challenge binds the document to a verifier-chosen nonce.
export interface Challenge {
  nonce: string;
  reportData: string;
  reportDataAlgorithm: string;
}

// EndorsedHashes are the SHA-256 hashes of the two endorsed sections,
// bound into the quote's REPORT_DATA.
export interface EndorsedHashes {
  cryptoMaterialHash: string;
  deviceEvidenceHash: string;
}

// CPUEvidence is the hardware quote and the endorsed-section hashes it binds.
export interface CPUEvidence {
  format: string;
  reportBase64: string;
  endorsed: EndorsedHashes;
}

// CryptoMaterialItem is one endorsed key: the item format URI fully
// determines how data (lowercase hex) is interpreted.
export interface CryptoMaterialItem {
  id: string;
  format: string;
  data: string;
}

// CryptoMaterialSection is the endorsed crypto_material section envelope.
export interface CryptoMaterialSection {
  format: string;
  items: CryptoMaterialItem[];
}

// DeviceEvidenceItem is one device's evidence; the item format URI versions
// the evidence payload (retained as raw JSON text).
export interface DeviceEvidenceItem {
  id: string;
  kind: string;
  vendor: string;
  format: string;
  evidence?: string;
}

// DeviceEvidenceSection is the endorsed device_evidence section envelope.
// Empty device evidence is items: [] — the section is always present.
export interface DeviceEvidenceSection {
  format: string;
  items: DeviceEvidenceItem[];
}

// CollateralEntry is one self-describing collateral record. Collateral is
// unendorsed transport: every entry is authenticated by its own signature
// chain during verification, so a tampered entry can only cause rejection.
// data is the exact raw JSON text of the entry's payload.
export interface CollateralEntry {
  id: string;
  role: string;
  format: string;
  subjects?: string[];
  data?: string;
}

// Document is the wire shape of a v3 attestation document. The endorsed
// sections travel base64-encoded: the builder serializes each section once
// and the encoded string carries those exact bytes, so every verifier
// recovers them with a plain base64 decode — no re-serialization, no
// canonicalization, no raw-span extraction (the same envelope discipline as
// DSSE and JWS).
export interface Document {
  format: string;
  challenge: Challenge;
  cpuEvidence: CPUEvidence;
  cryptoMaterial: string;
  deviceEvidence: string;
  collateral: CollateralEntry[];

  // Retained by parseDocument (Go: unexported fields).
  cryptoMaterialBytes: Uint8Array;
  deviceEvidenceBytes: Uint8Array;
  cryptoMaterialSection: CryptoMaterialSection;
  deviceEvidenceSection: DeviceEvidenceSection;
}

// AMDVCEKCollateral is the data of a CollateralAMDVCEKV1Format entry.
export interface AMDVCEKCollateral {
  vcekDerBase64: string;
  certChainPem: string;
}

// AMDCRLCollateral is the data of a CollateralAMDCRLV1Format entry.
export interface AMDCRLCollateral {
  crlDerBase64: string;
}

// PCSResponse is one captured Intel PCS response.
export interface PCSResponse {
  url: string;
  headers: Map<string, string[]>;
  bodyBase64: string;
}

// IntelPCSCollateral is the data of a CollateralIntelPCSV1Format entry:
// Intel PCS responses captured verbatim so a verifier can replay them
// instead of fetching. Headers are included because Intel delivers issuer
// chains in response headers.
export interface IntelPCSCollateral {
  responses?: PCSResponse[];
}

// SigstoreCollateral is the data of a sigstore-code or sigstore-platform
// reference-values entry. repo and tag are informational; trust comes from
// verifying sigstoreBundle against the expected signing identity and digest.
export interface SigstoreCollateral {
  repo: string;
  tag: string;
  digest: string;
  sigstoreBundle: Uint8Array;
}

// FreshnessCollateral carries the independently signed witness bundle for
// the Sigstore artifact selected by its collateral entry ID.
export interface FreshnessCollateral {
  sigstoreBundle: Uint8Array;
}

// Wire schemas (Go: struct json tags).

const documentSchema: Schema = structOf({
  format: field("format", str),
  challenge: field(
    "challenge",
    structOf({
      nonce: field("nonce", str),
      report_data: field("reportData", str),
      report_data_algorithm: field("reportDataAlgorithm", str),
    }),
  ),
  cpu_evidence: field(
    "cpuEvidence",
    structOf({
      format: field("format", str),
      report_base64: field("reportBase64", str),
      endorsed: field(
        "endorsed",
        structOf({
          crypto_material_hash: field("cryptoMaterialHash", str),
          device_evidence_hash: field("deviceEvidenceHash", str),
        }),
      ),
    }),
  ),
  crypto_material: field("cryptoMaterial", str),
  device_evidence: field("deviceEvidence", str),
  collateral: field(
    "collateral",
    arrayOf(
      structOf({
        id: field("id", str),
        role: field("role", str),
        format: field("format", str),
        subjects: field("subjects", arrayOf(str)),
        data: field("data", raw),
      }),
    ),
  ),
});

const cryptoMaterialSectionSchema: Schema = structOf({
  format: field("format", str),
  items: field(
    "items",
    arrayOf(
      structOf({
        id: field("id", str),
        format: field("format", str),
        data: field("data", str),
      }),
    ),
  ),
});

const deviceEvidenceSectionSchema: Schema = structOf({
  format: field("format", str),
  items: field(
    "items",
    arrayOf(
      structOf({
        id: field("id", str),
        kind: field("kind", str),
        vendor: field("vendor", str),
        format: field("format", str),
        evidence: field("evidence", raw),
      }),
    ),
  ),
});

const sigstoreCollateralSchema: Schema = structOf({
  repo: field("repo", str),
  tag: field("tag", str),
  digest: field("digest", str),
  sigstore_bundle: field("sigstoreBundle", raw),
});

const freshnessCollateralSchema: Schema = structOf({
  sigstore_bundle: field("sigstoreBundle", raw),
});

const amdVCEKCollateralSchema: Schema = structOf({
  vcek_der_base64: field("vcekDerBase64", str),
  cert_chain_pem: field("certChainPem", str),
});

const amdCRLCollateralSchema: Schema = structOf({
  crl_der_base64: field("crlDerBase64", str),
});

const intelPCSCollateralSchema: Schema = structOf({
  responses: field(
    "responses",
    arrayOf(
      structOf({
        url: field("url", str),
        headers: field("headers", mapOf(arrayOf(str))),
        body_base64: field("bodyBase64", str),
      }),
    ),
  ),
});

function envelopeError(message: string): VerificationError {
  return new VerificationError("ENVELOPE_REJECTED", message);
}

function reraise(err: unknown, layer: "ENVELOPE_REJECTED" | "PROVENANCE_REJECTED" | "QUOTE_REJECTED"): never {
  if (err instanceof VerificationError) throw err;
  throw new VerificationError(layer, err instanceof Error ? err.message : String(err));
}

// computeReportData derives the 64-byte REPORT_DATA per the
// https://tinfoil.sh/report-data/v1 algorithm: SHA-256 over the algorithm
// URI (domain-separation label) followed by the three fixed-length 32-byte
// inputs in order.
export function computeReportData(
  nonce: Uint8Array,
  cryptoMaterialHash: Uint8Array,
  deviceEvidenceHash: Uint8Array,
): Uint8Array {
  if (nonce.length !== 32 || cryptoMaterialHash.length !== 32 || deviceEvidenceHash.length !== 32) {
    throw envelopeError(
      `report data inputs must be 32 bytes each (got ${nonce.length}, ${cryptoMaterialHash.length}, ${deviceEvidenceHash.length})`,
    );
  }
  const out = new Uint8Array(64);
  out.set(sha256(utf8Encode(ReportDataV1Algorithm), nonce, cryptoMaterialHash, deviceEvidenceHash), 0);
  return out;
}

// parseDocument strictly parses a v3 document (Go: envelope.Parse): unknown
// members reject (case-sensitively), duplicate member names reject
// everywhere, hex must be lowercase, base64 canonical, and item ids unique.
// The endorsed sections are retained as raw bytes for hashing.
interface WireDocument {
  format: string;
  challenge: Challenge;
  cpuEvidence: CPUEvidence;
  cryptoMaterial: string;
  deviceEvidence: string;
  collateral?: CollateralEntry[];
}

export function parseDocument(docBytes: Uint8Array): Document {
  let wire: WireDocument;
  try {
    wire = unmarshal(docBytes, documentSchema) as WireDocument;
  } catch (err) {
    throw envelopeError(`parsing attestation document: ${err instanceof Error ? err.message : String(err)}`);
  }

  try {
    if (wire.format !== AttestationV3Format) {
      throw new Error(`unsupported document format ${JSON.stringify(wire.format)}`);
    }
    if (wire.challenge.reportDataAlgorithm !== ReportDataV1Algorithm) {
      throw new Error(`unsupported report_data_algorithm ${JSON.stringify(wire.challenge.reportDataAlgorithm)}`);
    }
    decodeLowerHex("challenge.nonce", wire.challenge.nonce, NonceSize);
    decodeLowerHex("challenge.report_data", wire.challenge.reportData, 64);
    decodeLowerHex("cpu_evidence.endorsed.crypto_material_hash", wire.cpuEvidence.endorsed.cryptoMaterialHash, 32);
    decodeLowerHex("cpu_evidence.endorsed.device_evidence_hash", wire.cpuEvidence.endorsed.deviceEvidenceHash, 32);
    if (wire.cpuEvidence.format === "" || wire.cpuEvidence.reportBase64 === "") {
      throw new Error("cpu_evidence is incomplete");
    }
    if (wire.cryptoMaterial === "") {
      throw new Error("crypto_material section is missing");
    }
    if (wire.deviceEvidence === "") {
      throw new Error("device_evidence section is missing");
    }
    const cryptoBytes = decodeCanonicalBase64("crypto_material", wire.cryptoMaterial);
    const deviceBytes = decodeCanonicalBase64("device_evidence", wire.deviceEvidence);

    let cm: { format: string; items?: CryptoMaterialItem[] };
    try {
      cm = unmarshal(cryptoBytes, cryptoMaterialSectionSchema) as typeof cm;
    } catch (err) {
      throw new Error(`parsing crypto_material: ${err instanceof Error ? err.message : String(err)}`);
    }
    if (cm.format !== CryptoMaterialV1Format) {
      throw new Error(`unsupported crypto_material section format ${JSON.stringify(cm.format)}`);
    }
    if (cm.items === undefined) {
      throw new Error("crypto_material.items is missing");
    }
    let seen = new Set<string>();
    for (const item of cm.items) {
      if (item.id === "" || item.format === "") {
        throw new Error("crypto_material item is incomplete");
      }
      if (seen.has(item.id)) {
        throw new Error(`duplicate crypto_material item id ${JSON.stringify(item.id)}`);
      }
      seen.add(item.id);
      switch (item.format) {
        case KeySPKIFPSHA256V1Format:
        case KeyX25519HPKEV1Format:
          // Known key formats are exactly 32 bytes; reject short, empty,
          // or odd-length material before callers trust it.
          decodeLowerHex(`crypto_material item ${JSON.stringify(item.id)} data`, item.data, 32);
          break;
        default:
          // Unknown formats still must carry non-empty, decodable
          // lowercase hex: the character class alone would admit
          // odd-length strings that no hex decoder accepts.
          if (item.data === "") {
            throw new Error(`crypto_material item ${JSON.stringify(item.id)} data is empty`);
          }
          if (!isLowerHex(item.data) || item.data.length % 2 !== 0) {
            throw new Error(`crypto_material item ${JSON.stringify(item.id)} data is not lowercase hex`);
          }
      }
    }

    let de: { format: string; items?: DeviceEvidenceItem[] };
    try {
      de = unmarshal(deviceBytes, deviceEvidenceSectionSchema) as typeof de;
    } catch (err) {
      throw new Error(`parsing device_evidence: ${err instanceof Error ? err.message : String(err)}`);
    }
    if (de.format !== DeviceEvidenceV1Format) {
      throw new Error(`unsupported device_evidence section format ${JSON.stringify(de.format)}`);
    }
    if (de.items === undefined) {
      throw new Error("device_evidence.items is missing");
    }
    seen = new Set<string>();
    for (const item of de.items) {
      if (item.id === "") {
        throw new Error("device_evidence item has no id");
      }
      if (seen.has(item.id)) {
        throw new Error(`duplicate device_evidence item id ${JSON.stringify(item.id)}`);
      }
      seen.add(item.id);
    }

    const collateral = wire.collateral ?? [];
    seen = new Set<string>();
    for (let i = 0; i < collateral.length; i++) {
      const entry = collateral[i];
      if (entry.id === "" || entry.format === "") {
        throw new Error(`collateral entry ${i} is incomplete`);
      }
      if (seen.has(entry.id)) {
        throw new Error(`duplicate collateral entry id ${JSON.stringify(entry.id)}`);
      }
      seen.add(entry.id);
      if (entry.role !== RoleEndorsement && entry.role !== RoleReferenceValues) {
        throw new Error(`collateral entry ${JSON.stringify(entry.id)} has unknown role ${JSON.stringify(entry.role)}`);
      }
    }

    return {
      format: wire.format,
      challenge: wire.challenge,
      cpuEvidence: wire.cpuEvidence,
      cryptoMaterial: wire.cryptoMaterial,
      deviceEvidence: wire.deviceEvidence,
      collateral,
      cryptoMaterialBytes: cryptoBytes,
      deviceEvidenceBytes: deviceBytes,
      cryptoMaterialSection: cm as CryptoMaterialSection,
      deviceEvidenceSection: de as DeviceEvidenceSection,
    };
  } catch (err) {
    reraise(err, "ENVELOPE_REJECTED");
  }
}

// check parses a v3 document and checks the challenge bindings (Go:
// envelope.Check): nonce equality, endorsed-section hash recomputation, and
// REPORT_DATA recomputation. It returns the document and the expected
// REPORT_DATA the CPU quote must bind. A check is not authentication:
// nothing in the document is trusted until the quote proves the hardware
// bound that REPORT_DATA.
export function check(
  docBytes: Uint8Array,
  expectedNonce: Uint8Array,
): { doc: Document; reportData: Uint8Array } {
  if (expectedNonce.length !== NonceSize) {
    throw envelopeError(`expected nonce must be ${NonceSize} bytes, got ${expectedNonce.length}`);
  }
  const doc = parseDocument(docBytes);
  if (doc.challenge.nonce !== encodeHex(expectedNonce)) {
    throw envelopeError("challenge nonce does not match the expected nonce");
  }

  const cryptoHash = sha256(doc.cryptoMaterialBytes);
  const deviceHash = sha256(doc.deviceEvidenceBytes);
  if (encodeHex(cryptoHash) !== doc.cpuEvidence.endorsed.cryptoMaterialHash) {
    throw envelopeError("crypto_material hash does not match cpu_evidence.endorsed.crypto_material_hash");
  }
  if (encodeHex(deviceHash) !== doc.cpuEvidence.endorsed.deviceEvidenceHash) {
    throw envelopeError("device_evidence hash does not match cpu_evidence.endorsed.device_evidence_hash");
  }

  const reportData = computeReportData(expectedNonce, cryptoHash, deviceHash);
  if (encodeHex(reportData) !== doc.challenge.reportData) {
    throw envelopeError("challenge report_data does not match the recomputed value");
  }
  return { doc, reportData };
}

// cryptoMaterialItems returns the parsed crypto_material items.
export function cryptoMaterialItems(doc: Document): { id: string; format: string; data: string }[] {
  return doc.cryptoMaterialSection?.items ?? [];
}

// deviceEvidenceItems returns the parsed device_evidence items.
export function deviceEvidenceItems(doc: Document): DeviceEvidenceItem[] {
  return doc.deviceEvidenceSection?.items ?? [];
}

// cryptoMaterialItem returns the crypto_material item with the given id.
export function cryptoMaterialItem(doc: Document, id: string): CryptoMaterialItem | undefined {
  return cryptoMaterialItems(doc).find((item) => item.id === id);
}

// endorsementCollateral returns the first endorsement-role collateral entry
// with the given format whose subjects include subject.
export function endorsementCollateral(
  doc: Document,
  format: string,
  subject: string,
): { id: string; data: unknown } | undefined {
  for (const entry of doc.collateral) {
    if (entry.role !== RoleEndorsement || entry.format !== format) continue;
    if ((entry.subjects ?? []).includes(subject)) return { id: entry.id, data: entry.data };
  }
  return undefined;
}

// referenceValuesCollateral returns the first reference-values collateral
// entry with the given format, parsed as a Sigstore collateral payload. A
// document without such an entry throws a CollateralNotFoundError. Errors
// carry PROVENANCE_REJECTED: in the verification flow this lookup is the
// first step of reference-values authentication.
export function referenceValuesCollateral(doc: Document, format: string): SigstoreCollateral {
  for (const entry of doc.collateral) {
    if (entry.role !== RoleReferenceValues || entry.format !== format) continue;
    let sc: { repo: string; tag: string; digest: string; sigstoreBundle?: string };
    try {
      sc = unmarshal(entry.data ?? "", sigstoreCollateralSchema) as typeof sc;
    } catch (err) {
      throw new VerificationError(
        "PROVENANCE_REJECTED",
        `parsing ${format} collateral entry ${JSON.stringify(entry.id)}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    return {
      repo: sc.repo,
      tag: sc.tag,
      digest: sc.digest,
      sigstoreBundle: utf8Encode(sc.sigstoreBundle ?? ""),
    };
  }
  throw new CollateralNotFoundError(
    "PROVENANCE_REJECTED",
    `collateral entry not found: document carries no ${format} reference-values entry`,
  );
}

// freshnessCollateral returns the freshness witness bundle for the Sigstore
// reference-values entry selected by its collateral entry ID, rejecting
// duplicate entries.
export function freshnessCollateral(doc: Document, id: string): { sigstoreBundle: Uint8Array } {
  let found: { sigstoreBundle: Uint8Array } | undefined;
  for (const entry of doc.collateral) {
    if (entry.id !== id || entry.role !== RoleReferenceValues || entry.format !== CollateralSigstoreFreshnessV1Format) {
      continue;
    }
    if (found !== undefined) {
      throw new VerificationError(
        "PROVENANCE_REJECTED",
        `document carries duplicate freshness collateral entry ${JSON.stringify(id)}`,
      );
    }
    let fc: { sigstoreBundle?: string };
    try {
      fc = unmarshal(entry.data ?? "", freshnessCollateralSchema) as typeof fc;
    } catch (err) {
      throw new VerificationError(
        "PROVENANCE_REJECTED",
        `parsing freshness collateral entry ${JSON.stringify(entry.id)}: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    found = { sigstoreBundle: utf8Encode(fc.sigstoreBundle ?? "") };
  }
  if (found === undefined) {
    throw new CollateralNotFoundError(
      "PROVENANCE_REJECTED",
      `collateral entry not found: document carries no ${CollateralSigstoreFreshnessV1Format} reference-values entry ${JSON.stringify(id)}`,
    );
  }
  return found;
}

// Typed strict parsers for endorsement collateral payloads, consumed by the
// quote layer (errors carry QUOTE_REJECTED, matching Go's step attribution).

export function parseAMDVCEKCollateral(data: unknown): AMDVCEKCollateral {
  try {
    return unmarshal((data as string | undefined) ?? "", amdVCEKCollateralSchema) as AMDVCEKCollateral;
  } catch (err) {
    reraise(err, "QUOTE_REJECTED");
  }
}

export function parseAMDCRLCollateral(data: unknown): AMDCRLCollateral {
  try {
    return unmarshal((data as string | undefined) ?? "", amdCRLCollateralSchema) as AMDCRLCollateral;
  } catch (err) {
    reraise(err, "QUOTE_REJECTED");
  }
}

export function parseIntelPCSCollateral(data: unknown): IntelPCSCollateral {
  try {
    return unmarshal((data as string | undefined) ?? "", intelPCSCollateralSchema) as IntelPCSCollateral;
  } catch (err) {
    reraise(err, "QUOTE_REJECTED");
  }
}
