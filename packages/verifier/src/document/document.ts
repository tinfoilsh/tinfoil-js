/**
 * The v3 attestation document wire format and its strict parsing, which
 * checks the challenge against the caller's nonce. Parsing authenticates
 * nothing: the CPU quote must prove the hardware bound the recomputed
 * REPORT_DATA before any part of the document is trusted.
 */
import { concat, sha256, toHex, utf8 } from "../internal/bytes.js";
import { decodeBase64, decodeLowerHex, isLowerHex } from "../internal/canonical.js";
import { arr, object, raw, str, struct } from "../internal/json/decode.js";
import { cloneJsonValue, strictParse, type JsonObject, type JsonValue } from "../internal/json/index.js";
import {
  ARTIFACT_FRESHNESS_V1_FORMAT,
  CONFIG_ID,
  configPlatform,
  decode as decodeCollateralSet,
  decodeEntries,
  FORMAT_V2,
  FORMAT_V3,
  NotFoundError,
  SIGSTORE_CODE_V1_FORMAT,
  SIGSTORE_FRESHNESS_V1_FORMAT,
  SIGSTORE_PLATFORM_V1_FORMAT,
  type CollateralSet,
  type CpuEndorsements,
} from "./collateral/collateral.js";
import type { ConfigEndorsement } from "./collateral/config.js";
import { RUNTIME_ID, type RuntimeCollateral } from "./collateral/runtime.js";
import type { Freshness, SigstoreRef } from "./collateral/sigstore.js";

export type { CpuEndorsements } from "./collateral/collateral.js";

// Format registry (v3).
export const ATTESTATION_V3_FORMAT = "https://tinfoil.sh/predicate/attestation/v3";
export const REPORT_DATA_V1_ALGORITHM = "https://tinfoil.sh/report-data/v1";
export const CRYPTO_MATERIAL_V1_FORMAT = "https://tinfoil.sh/crypto-material/v1";
export const DEVICE_EVIDENCE_V1_FORMAT = "https://tinfoil.sh/device-evidence/v1";
export const SEV_SNP_REPORT_V1_FORMAT = "https://tinfoil.sh/format/sev-snp-report/v1";
export const TDX_QUOTE_V1_FORMAT = "https://tinfoil.sh/format/tdx-quote/v1";
export const NVIDIA_GPU_EVIDENCE_V1_FORMAT = "https://tinfoil.sh/format/nvidia-gpu-evidence/v1";
export const KEY_SPKI_FP_SHA256_V1_FORMAT = "https://tinfoil.sh/key/spki-fp-sha256/v1";
export const KEY_SPKI_V1_FORMAT = "https://tinfoil.sh/key/spki/v1";
export const KEY_X25519_HPKE_V1_FORMAT = "https://tinfoil.sh/key/x25519-hpke/v1";

// Conventional crypto-material identifiers.
export const CRYPTO_MATERIAL_ID_TLS = "tls";
export const CRYPTO_MATERIAL_ID_HPKE = "hpke";

/** Required challenge nonce size in bytes. */
export const NONCE_SIZE = 32;

/**
 * A mistake in the caller's input to {@link parse} (a nonce of the wrong
 * length), as opposed to a document that fails to parse. Callers that
 * classify failures can treat it as a caller error rather than a rejected
 * document.
 */
export class InvalidInputError extends Error {
  constructor(message: string) {
    super(`invalid input: ${message}`);
    this.name = "InvalidInputError";
  }
}

/** A document's decoded hardware evidence. */
export interface CpuEvidence {
  /** Selects the platform, e.g. SEV_SNP_REPORT_V1_FORMAT. */
  readonly format: string;
  /** The raw SEV-SNP report or TDX quote. */
  readonly report: Uint8Array;
}

/** One endorsed key; the format URI determines how `data` (lowercase hex) is read. */
export interface CryptoMaterialItem {
  readonly id: string;
  readonly format: string;
  readonly data: string;
}

/** One device's evidence; the format URI versions the payload. */
export interface DeviceEvidenceItem {
  readonly id: string;
  readonly kind: string;
  readonly vendor: string;
  readonly format: string;
  /** Undefined when the member is absent. */
  readonly evidence: JsonValue | undefined;
}

/** A parsed v3 attestation document. Accessors return copies, as in the reference. */
export class Document {
  readonly #d: DecodedDocument;

  /** @internal Build with {@link parse} or {@link dangerousTestOnlyDecode}. */
  constructor(fields: DecodedDocument) {
    this.#d = fields;
  }

  /** The collateral format, selecting a verification policy; "" decodes as FORMAT_V2. */
  collateralFormat(): string {
    return this.#d.collateralFormat === "" ? FORMAT_V2 : this.#d.collateralFormat;
  }

  cpuEvidence(): CpuEvidence {
    return { format: this.#d.cpuEvidence.format, report: this.#d.cpuEvidence.report.slice() };
  }

  /** Endorsement collateral the evidence format uses, for the "cpu" subject; absent collateral is undefined. */
  cpuEndorsements(): CpuEndorsements {
    const cpu = this.#d.collateral.cpu;
    switch (this.#d.cpuEvidence.format) {
      case SEV_SNP_REPORT_V1_FORMAT:
        return {
          amdVcek: cpu.amdVcek && { vcekDer: cpu.amdVcek.vcekDer.slice(), certChainPem: cpu.amdVcek.certChainPem },
          amdCrl: cpu.amdCrl && { crlDer: cpu.amdCrl.crlDer.slice() },
        };
      case TDX_QUOTE_V1_FORMAT:
        return {
          intelPcs: cpu.intelPcs && {
            responses: cpu.intelPcs.responses.map((r) => ({
              url: r.url,
              headers: r.headers && new Map([...r.headers].map(([k, v]) => [k, [...v]])),
              body: r.body.slice(),
            })),
          },
        };
      default:
        return {};
    }
  }

  cryptoMaterialItems(): CryptoMaterialItem[] {
    return this.#d.cryptoMaterial.map((i) => ({ ...i }));
  }

  cryptoMaterialItem(id: string): CryptoMaterialItem | undefined {
    const item = this.#d.cryptoMaterial.find((i) => i.id === id);
    return item && { ...item };
  }

  deviceEvidenceItems(): DeviceEvidenceItem[] {
    return this.#d.deviceEvidence.map((i) => ({ ...i, evidence: cloneOpt(i.evidence) }));
  }

  /** The code-provenance entry. Throws NotFoundError when absent. */
  sigstoreCode(): SigstoreRef {
    return sigstoreRef(this.#d.collateral.sigstoreCode, SIGSTORE_CODE_V1_FORMAT);
  }

  /** The platform-endorsements entry. Throws NotFoundError when absent. */
  sigstorePlatform(): SigstoreRef {
    return sigstoreRef(this.#d.collateral.sigstorePlatform, SIGSTORE_PLATFORM_V1_FORMAT);
  }

  /** The freshness proof with the given collateral id. Throws NotFoundError when absent. */
  freshness(id: string): Freshness {
    const f = this.#d.collateral.freshness.get(id);
    if (f === undefined) {
      throw new NotFoundError(`document carries no ${SIGSTORE_FRESHNESS_V1_FORMAT} reference-values entry "${id}"`);
    }
    return { format: f.format, bundle: cloneJsonValue(f.bundle) };
  }

  /** The decoded, unauthenticated config approval (v3 collateral). Throws NotFoundError when absent. */
  configEndorsement(): ConfigEndorsement {
    const c = this.#d.collateral.config;
    if (c === undefined) throw new NotFoundError(`document carries no "${CONFIG_ID}" reference-values entry`);
    return {
      reference: c.reference,
      ...(c.config === undefined ? {} : { config: c.config.slice() }),
      bundle: cloneOpt(c.bundle),
      ...(c.issuer === undefined ? {} : { issuer: c.issuer.slice() }),
    };
  }

  /** The decoded, unauthenticated runtime approval (v3 collateral). Throws NotFoundError when absent. */
  runtime(): RuntimeCollateral {
    const r = this.#d.collateral.runtime;
    if (r === undefined) throw new NotFoundError(`document carries no "${RUNTIME_ID}" reference-values entry`);
    return { ...r, manifest: r.manifest.slice(), bundle: cloneJsonValue(r.bundle) };
  }

  /** The unambiguous platform reference of a config-based document (v3 collateral). */
  configPlatform(): SigstoreRef {
    return cloneRef(configPlatform(this.#d.collateral));
  }

  /**
   * The REPORT_DATA the CPU quote must bind, recomputed by {@link parse}.
   * Undefined for a document that wasn't bound to a nonce, whose zero
   * REPORT_DATA must never be compared against a quote.
   */
  expectedReportData(): Uint8Array | undefined {
    return this.#d.reportData?.slice();
  }
}

function sigstoreRef(ref: SigstoreRef | undefined, format: string): SigstoreRef {
  if (ref === undefined) throw new NotFoundError(`document carries no ${format} reference-values entry`);
  return cloneRef(ref);
}

function cloneRef(ref: SigstoreRef): SigstoreRef {
  return { ...ref, bundle: cloneJsonValue(ref.bundle) };
}

function cloneOpt(v: JsonValue | undefined): JsonValue | undefined {
  return v === undefined ? undefined : cloneJsonValue(v);
}

/** @internal Everything {@link decode} recovers from the wire. */
export interface DecodedDocument {
  readonly challenge: { readonly nonce: string; readonly reportData: string };
  readonly cpuEvidence: CpuEvidence;
  /** Lowercase hex, as sent. */
  readonly endorsedHashes: { readonly cryptoMaterial: string; readonly deviceEvidence: string };
  /** The exact section bytes, as base64-decoded; hashed for binding. */
  readonly cryptoMaterialRaw: Uint8Array;
  readonly deviceEvidenceRaw: Uint8Array;
  readonly cryptoMaterial: readonly CryptoMaterialItem[];
  readonly deviceEvidence: readonly DeviceEvidenceItem[];
  readonly collateralFormat: string;
  readonly collateral: CollateralSet;
  /** Set by bind(): the recomputed REPORT_DATA. */
  readonly reportData?: Uint8Array;
}

/**
 * Strictly parses a v3 document and checks its challenge bindings against
 * `expectedNonce`: nonce equality, endorsed-section hash recomputation, and
 * REPORT_DATA recomputation. A nonce of the wrong length throws
 * InvalidInputError; any other failure throws a plain Error.
 *
 * Strict means: unknown members reject (case-sensitively), duplicate member
 * names reject everywhere, hex must be lowercase, base64 canonical, and item
 * ids unique.
 */
export async function parse(docBytes: Uint8Array, expectedNonce: Uint8Array): Promise<Document> {
  if (expectedNonce.length !== NONCE_SIZE) {
    throw new InvalidInputError(`expected nonce must be ${NONCE_SIZE} bytes, got ${expectedNonce.length}`);
  }
  // Snapshot the caller's buffer: bind awaits between the nonce comparison and
  // the REPORT_DATA derivation, and both must see the same bytes.
  return new Document(await bind(decode(docBytes), expectedNonce.slice()));
}

/**
 * Decodes a document without binding it to a nonce, so the conformance
 * adapter can drive a single layer. Not exported from the package entry.
 */
export async function dangerousTestOnlyDecode(docBytes: Uint8Array): Promise<Document> {
  return new Document(decode(docBytes));
}

/**
 * Derives REPORT_DATA (https://tinfoil.sh/report-data/v1): SHA-256 over the
 * algorithm URI then the three 32-byte inputs, in bytes [0:32]; [32:64] zero.
 */
export async function computeReportData(
  nonce: Uint8Array,
  cryptoMaterialHash: Uint8Array,
  deviceEvidenceHash: Uint8Array,
): Promise<Uint8Array> {
  if (nonce.length !== 32 || cryptoMaterialHash.length !== 32 || deviceEvidenceHash.length !== 32) {
    throw new Error(
      `report data inputs must be 32 bytes each (got ${nonce.length}, ${cryptoMaterialHash.length}, ${deviceEvidenceHash.length})`,
    );
  }
  const out = new Uint8Array(64);
  out.set(await sha256(concat(utf8(REPORT_DATA_V1_ALGORITHM), nonce, cryptoMaterialHash, deviceEvidenceHash)));
  return out;
}

/** A cryptographically random NONCE_SIZE-byte challenge. */
export function randomNonce(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(NONCE_SIZE));
}

// --- internal (document.go unexported helpers) ---

const DOCUMENT_MEMBERS = [
  "format",
  "challenge",
  "cpu_evidence",
  "crypto_material",
  "device_evidence",
  "collateral_format",
  "collateral",
] as const;

/** Strict unmarshal → format → challenge → cpu_evidence → sections → collateral. */
export function decode(docBytes: Uint8Array): DecodedDocument {
  let root: JsonObject;
  let challenge: JsonObject;
  let cpu: JsonObject;
  let endorsed: JsonObject;
  try {
    root = object(strictParse(docBytes), "attestation document", DOCUMENT_MEMBERS);
    challenge = struct(root, "challenge", ["nonce", "report_data", "report_data_algorithm"]);
    cpu = struct(root, "cpu_evidence", ["format", "report_base64", "endorsed"]);
    endorsed = struct(cpu, "endorsed", ["crypto_material_hash", "device_evidence_hash"]);
  } catch (err) {
    throw new Error(`parsing attestation document: ${(err as Error).message}`);
  }
  // The whole document (including the collateral array's shape) is decoded
  // before any semantic check, so every type error surfaces first.
  const scalars = readScalars(root, challenge, cpu, endorsed);
  const entries = parseStage("attestation document", () => decodeEntries(raw(root, "collateral")));

  if (scalars.format !== ATTESTATION_V3_FORMAT) throw new Error(`unsupported document format "${scalars.format}"`);

  // challenge.parse()
  if (scalars.reportDataAlgorithm !== REPORT_DATA_V1_ALGORITHM) {
    throw new Error(`unsupported challenge.report_data_algorithm "${scalars.reportDataAlgorithm}"`);
  }
  decodeLowerHex("challenge.nonce", scalars.nonce, NONCE_SIZE);
  decodeLowerHex("challenge.report_data", scalars.reportData, 64);

  // cpu_evidence.parse()
  decodeLowerHex("cpu_evidence.endorsed.crypto_material_hash", scalars.cmHash, 32);
  decodeLowerHex("cpu_evidence.endorsed.device_evidence_hash", scalars.deHash, 32);
  if (scalars.cpuFormat === "" || scalars.reportBase64 === "") throw new Error("cpu_evidence is incomplete");
  const report = decodeBase64("cpu_evidence.report_base64", scalars.reportBase64);

  const cm = parseCryptoMaterial(scalars.cryptoMaterial);
  const de = parseDeviceEvidence(scalars.deviceEvidence);
  const collateral = decodeCollateralSetFor(scalars.collateralFormat, entries);

  return {
    challenge: { nonce: scalars.nonce, reportData: scalars.reportData },
    cpuEvidence: { format: scalars.cpuFormat, report },
    endorsedHashes: { cryptoMaterial: scalars.cmHash, deviceEvidence: scalars.deHash },
    cryptoMaterialRaw: cm.raw,
    deviceEvidenceRaw: de.raw,
    cryptoMaterial: cm.items,
    deviceEvidence: de.items,
    collateralFormat: scalars.collateralFormat,
    collateral,
  };
}

function readScalars(root: JsonObject, challenge: JsonObject, cpu: JsonObject, endorsed: JsonObject) {
  return parseStage("attestation document", () => ({
    format: str(root, "format"),
    cryptoMaterial: str(root, "crypto_material"),
    deviceEvidence: str(root, "device_evidence"),
    collateralFormat: str(root, "collateral_format"),
    nonce: str(challenge, "nonce"),
    reportData: str(challenge, "report_data"),
    reportDataAlgorithm: str(challenge, "report_data_algorithm"),
    cpuFormat: str(cpu, "format"),
    reportBase64: str(cpu, "report_base64"),
    cmHash: str(endorsed, "crypto_material_hash"),
    deHash: str(endorsed, "device_evidence_hash"),
  }));
}

function parseStage<T>(what: string, f: () => T): T {
  try {
    return f();
  } catch (err) {
    throw new Error(`parsing ${what}: ${(err as Error).message}`);
  }
}

/** Checks nonce equality, section hashes and REPORT_DATA; returns the bound fields. */
export async function bind(doc: DecodedDocument, expectedNonce: Uint8Array): Promise<DecodedDocument> {
  if (doc.challenge.nonce !== toHex(expectedNonce)) {
    throw new Error("challenge nonce does not match the expected nonce");
  }
  const cryptoHash = await sha256(doc.cryptoMaterialRaw);
  const deviceHash = await sha256(doc.deviceEvidenceRaw);
  if (toHex(cryptoHash) !== doc.endorsedHashes.cryptoMaterial) {
    throw new Error("crypto_material hash does not match cpu_evidence.endorsed.crypto_material_hash");
  }
  if (toHex(deviceHash) !== doc.endorsedHashes.deviceEvidence) {
    throw new Error("device_evidence hash does not match cpu_evidence.endorsed.device_evidence_hash");
  }
  const reportData = await computeReportData(expectedNonce, cryptoHash, deviceHash);
  if (toHex(reportData) !== doc.challenge.reportData) {
    throw new Error("challenge report_data does not match the recomputed value");
  }
  return { ...doc, reportData };
}

/** Canonical base64 → strict JSON → crypto-material/v1 rules. Returns items and the raw bytes. */
export function parseCryptoMaterial(encoded: string): { items: CryptoMaterialItem[]; raw: Uint8Array } {
  if (encoded === "") throw new Error("crypto_material section is missing");
  const bytes = decodeBase64("crypto_material", encoded);
  const { format, list } = parseStage("crypto_material", () => {
    const o = object(strictParse(bytes), "crypto_material", ["format", "items"]);
    const list = arr(o, "items")?.map((v) => {
      const i = object(v, "crypto_material item", ["id", "format", "data"]);
      return { id: str(i, "id"), format: str(i, "format"), data: str(i, "data") };
    });
    return { format: str(o, "format"), list };
  });
  if (format !== CRYPTO_MATERIAL_V1_FORMAT) throw new Error(`unsupported crypto_material section format "${format}"`);
  if (list === undefined) throw new Error("crypto_material.items is missing");
  const seen = new Set<string>();
  for (const item of list) {
    if (item.id === "" || item.format === "") throw new Error("crypto_material item is incomplete");
    if (seen.has(item.id)) throw new Error(`duplicate crypto_material item id "${item.id}"`);
    seen.add(item.id);
    if (item.format === KEY_SPKI_FP_SHA256_V1_FORMAT || item.format === KEY_X25519_HPKE_V1_FORMAT) {
      decodeLowerHex(`crypto_material item "${item.id}" data`, item.data, 32);
    } else {
      if (item.data === "") throw new Error(`crypto_material item "${item.id}" data is empty`);
      if (!isLowerHex(item.data) || item.data.length % 2 !== 0) {
        throw new Error(`crypto_material item "${item.id}" data is not lowercase hex`);
      }
    }
  }
  return { items: list, raw: bytes };
}

/** Canonical base64 → strict JSON → device-evidence/v1 rules. Returns items and the raw bytes. */
export function parseDeviceEvidence(encoded: string): { items: DeviceEvidenceItem[]; raw: Uint8Array } {
  if (encoded === "") throw new Error("device_evidence section is missing");
  const bytes = decodeBase64("device_evidence", encoded);
  const { format, list } = parseStage("device_evidence", () => {
    const o = object(strictParse(bytes), "device_evidence", ["format", "items"]);
    const list = arr(o, "items")?.map((v): DeviceEvidenceItem => {
      const i = object(v, "device_evidence item", ["id", "kind", "vendor", "format", "evidence"]);
      return {
        id: str(i, "id"),
        kind: str(i, "kind"),
        vendor: str(i, "vendor"),
        format: str(i, "format"),
        evidence: raw(i, "evidence"),
      };
    });
    return { format: str(o, "format"), list };
  });
  if (format !== DEVICE_EVIDENCE_V1_FORMAT) throw new Error(`unsupported device_evidence section format "${format}"`);
  if (list === undefined) throw new Error("device_evidence.items is missing");
  const seen = new Set<string>();
  for (const item of list) {
    if (item.id === "") throw new Error("device_evidence item has no id");
    if (seen.has(item.id)) throw new Error(`duplicate device_evidence item id "${item.id}"`);
    seen.add(item.id);
  }
  return { items: list, raw: bytes };
}

/** Collateral-format rules: "", v2 or v3; v3 forbids sigstore-code; v2 forbids config and runtime. */
function decodeCollateralSetFor(format: string, entries: ReturnType<typeof decodeEntries>): CollateralSet {
  if (format !== "" && format !== FORMAT_V2 && format !== FORMAT_V3) {
    throw new Error(`unsupported collateral format "${format}"`);
  }
  const set = decodeCollateralSet(entries);
  if (format === FORMAT_V3) {
    if (set.sigstoreCode !== undefined) throw new Error(`legacy code collateral is incompatible with "${format}"`);
  } else if (set.config !== undefined || set.runtime !== undefined) {
    throw new Error(`config and runtime collateral require "${FORMAT_V3}"`);
  }
  for (const f of set.freshness.values()) {
    if ((format === FORMAT_V3) !== (f.format === ARTIFACT_FRESHNESS_V1_FORMAT)) {
      throw new Error(`freshness collateral is incompatible with "${format}"`);
    }
  }
  return set;
}

/** Collateral-format rules over raw entries (wire array). */
export function decodeCollateral(format: string, entries: JsonValue): CollateralSet {
  return decodeCollateralSetFor(format, decodeEntries(entries));
}
