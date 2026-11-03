/**
 * Test-only port of tinfoil-go verify/document/builder.go (document.Build).
 *
 * It serializes and hashes the endorsed sections, derives the REPORT_DATA they
 * bind, asks a quote generator to "sign" it, and assembles the document JSON,
 * so tests can make valid documents and then mutate them. Like Go's Build, the
 * input is held to the rules parse enforces before any quote is generated.
 *
 * Raw JSON members (collateral entry `data`, device `evidence`) are carried as
 * JSON text, as Go carries them as jsontext.Value, so tests can express
 * malformed or missing data.
 */
import { sha256, toHex } from "../../../src/v3/internal/bytes.js";
import { strictParse } from "../../../src/v3/internal/json/index.js";
import { FORMAT_V2 } from "../../../src/v3/document/collateral/collateral.js";
import {
  ATTESTATION_V3_FORMAT,
  computeReportData,
  CRYPTO_MATERIAL_V1_FORMAT,
  type CryptoMaterialItem,
  decodeCollateral,
  DEVICE_EVIDENCE_V1_FORMAT,
  InvalidInputError,
  NONCE_SIZE,
  parseCryptoMaterial,
  parseDeviceEvidence,
  REPORT_DATA_V1_ALGORITHM,
  SEV_SNP_REPORT_V1_FORMAT,
  TDX_QUOTE_V1_FORMAT,
} from "../../../src/v3/document/document.js";

/** A wire collateral entry (Go collateral.Entry). `data` is raw JSON text; undefined omits the member. */
export interface WireEntry {
  id?: string;
  role?: string;
  format?: string;
  /** Omitted from the wire when empty (Go `omitempty`). */
  subjects?: string[];
  data?: string;
}

/** A device_evidence item to build (Go DeviceEvidenceItem). `evidence` is raw JSON text; undefined is null. */
export interface BuildDeviceEvidenceItem {
  id?: string;
  kind?: string;
  vendor?: string;
  format?: string;
  evidence?: string;
}

/** Go document.BuildInput. */
export interface BuildInput {
  nonce: Uint8Array;
  cryptoMaterial?: CryptoMaterialItem[];
  deviceEvidence?: BuildDeviceEvidenceItem[];
  collateral?: WireEntry[];
  /** Empty or absent means legacy (v2). */
  collateralFormat?: string;
}

/** Go document.QuoteGenerator: returns the evidence format and the raw report or quote. */
export type QuoteGenerator = (
  reportData: Uint8Array,
) => { format: string; report: Uint8Array } | Promise<{ format: string; report: Uint8Array }>;

/** The serialized document shape (Go rawDocument), as a plain object tests can mutate. */
export interface RawDocument {
  format: string;
  challenge: { nonce: string; report_data: string; report_data_algorithm: string };
  cpu_evidence: {
    format: string;
    report_base64: string;
    endorsed: { crypto_material_hash: string; device_evidence_hash: string };
  };
  crypto_material: string;
  device_evidence: string;
  /** Omitted when empty (Go `omitempty`). */
  collateral_format?: string;
  collateral: WireEntry[];
}

const q = (s: string): string => JSON.stringify(s);

export function b64(bytes: Uint8Array | string): string {
  return Buffer.from(typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes).toString("base64");
}

/** Serializes one entry as Go json.Marshal(collateral.Entry) does. */
export function marshalEntry(e: WireEntry): string {
  let s = `{"id":${q(e.id ?? "")},"role":${q(e.role ?? "")},"format":${q(e.format ?? "")}`;
  if (e.subjects !== undefined && e.subjects.length > 0) s += `,"subjects":${JSON.stringify(e.subjects)}`;
  if (e.data !== undefined) s += `,"data":${e.data}`;
  return s + "}";
}

/** Serializes a collateral array; Go marshals a nil slice as []. */
export function marshalEntries(entries: readonly WireEntry[] | undefined): string {
  return `[${(entries ?? []).map(marshalEntry).join(",")}]`;
}

/** Serializes a document in Go's field order (format, challenge, cpu_evidence, sections, collateral). */
export function marshalDocument(raw: RawDocument): Uint8Array {
  const c = raw.challenge;
  const cpu = raw.cpu_evidence;
  let s =
    `{"format":${q(raw.format)}` +
    `,"challenge":{"nonce":${q(c.nonce)},"report_data":${q(c.report_data)},"report_data_algorithm":${q(c.report_data_algorithm)}}` +
    `,"cpu_evidence":{"format":${q(cpu.format)},"report_base64":${q(cpu.report_base64)}` +
    `,"endorsed":{"crypto_material_hash":${q(cpu.endorsed.crypto_material_hash)},"device_evidence_hash":${q(cpu.endorsed.device_evidence_hash)}}}` +
    `,"crypto_material":${q(raw.crypto_material)},"device_evidence":${q(raw.device_evidence)}`;
  if (raw.collateral_format !== undefined && raw.collateral_format !== "") {
    s += `,"collateral_format":${q(raw.collateral_format)}`;
  }
  s += `,"collateral":${marshalEntries(raw.collateral)}}`;
  return new TextEncoder().encode(s);
}

function marshalCryptoMaterial(items: readonly CryptoMaterialItem[]): Uint8Array {
  const list = items.map((i) => `{"id":${q(i.id)},"format":${q(i.format)},"data":${q(i.data)}}`).join(",");
  return new TextEncoder().encode(`{"format":${q(CRYPTO_MATERIAL_V1_FORMAT)},"items":[${list}]}`);
}

function marshalDeviceEvidence(items: readonly BuildDeviceEvidenceItem[]): Uint8Array {
  const list = items
    .map(
      (i) =>
        `{"id":${q(i.id ?? "")},"kind":${q(i.kind ?? "")},"vendor":${q(i.vendor ?? "")},"format":${q(i.format ?? "")},"evidence":${i.evidence ?? "null"}}`,
    )
    .join(",");
  return new TextEncoder().encode(`{"format":${q(DEVICE_EVIDENCE_V1_FORMAT)},"items":[${list}]}`);
}

interface Endorsed {
  cryptoMaterial: string;
  deviceEvidence: string;
  cryptoHash: Uint8Array;
  deviceHash: Uint8Array;
  reportData: Uint8Array;
}

/** Go endorse: serializes each section once, holds it to parse's rules, and derives REPORT_DATA. */
async function endorse(
  nonce: Uint8Array,
  cryptoMaterial: readonly CryptoMaterialItem[],
  deviceEvidence: readonly BuildDeviceEvidenceItem[],
): Promise<Endorsed> {
  if (nonce.length !== NONCE_SIZE) throw new Error(`nonce must be ${NONCE_SIZE} bytes, got ${nonce.length}`);
  const cryptoBytes = marshalCryptoMaterial(cryptoMaterial);
  const deviceBytes = marshalDeviceEvidence(deviceEvidence);
  const e = {
    cryptoMaterial: b64(cryptoBytes),
    deviceEvidence: b64(deviceBytes),
    cryptoHash: await sha256(cryptoBytes),
    deviceHash: await sha256(deviceBytes),
  };
  parseCryptoMaterial(e.cryptoMaterial);
  parseDeviceEvidence(e.deviceEvidence);
  return { ...e, reportData: await computeReportData(nonce, e.cryptoHash, e.deviceHash) };
}

function invalid(err: unknown): InvalidInputError {
  return new InvalidInputError((err as Error).message);
}

/** Go Build, also returning the assembled document object so tests can mutate and re-marshal it. */
export async function buildDocument(
  input: BuildInput,
  generateQuote: QuoteGenerator | undefined,
): Promise<{ raw: RawDocument; bytes: Uint8Array }> {
  if (generateQuote === undefined) throw new InvalidInputError("a quote generator is required");
  // Copied so a caller reusing its buffer cannot change the nonce mid-build.
  const nonce = input.nonce.slice();
  const collateralFormat = input.collateralFormat ?? "";
  const entries = input.collateral ?? [];
  let sections: Endorsed;
  try {
    sections = await endorse(nonce, input.cryptoMaterial ?? [], input.deviceEvidence ?? []);
  } catch (err) {
    throw invalid(err);
  }
  // Reject collateral parse would refuse before it costs a hardware quote.
  try {
    decodeCollateral(collateralFormat, strictParse(new TextEncoder().encode(marshalEntries(entries))));
  } catch (err) {
    throw invalid(err);
  }
  const { format, report } = await generateQuote(sections.reportData.slice());
  if (format !== SEV_SNP_REPORT_V1_FORMAT && format !== TDX_QUOTE_V1_FORMAT) {
    throw new Error(`quote generator returned unsupported evidence format ${q(format)}`);
  }
  if (report.length === 0) throw new Error("quote generator returned an empty report");

  const raw: RawDocument = {
    format: ATTESTATION_V3_FORMAT,
    challenge: {
      nonce: toHex(nonce),
      report_data: toHex(sections.reportData),
      report_data_algorithm: REPORT_DATA_V1_ALGORITHM,
    },
    cpu_evidence: {
      format,
      report_base64: b64(report),
      endorsed: {
        crypto_material_hash: toHex(sections.cryptoHash),
        device_evidence_hash: toHex(sections.deviceHash),
      },
    },
    crypto_material: sections.cryptoMaterial,
    device_evidence: sections.deviceEvidence,
    // Preserve the wire shape accepted by legacy v3 verifiers.
    collateral_format: collateralFormat === FORMAT_V2 ? undefined : collateralFormat || undefined,
    collateral: entries.map((e) => ({ ...e })),
  };
  return { raw, bytes: marshalDocument(raw) };
}

/** Go document.Build. */
export async function build(input: BuildInput, generateQuote: QuoteGenerator | undefined): Promise<Uint8Array> {
  return (await buildDocument(input, generateQuote)).bytes;
}

/** Go fakeQuote: a generator returning a fixed format and report, recording what it was asked to sign. */
export function fakeQuote(format: string, report: Uint8Array, signed?: { reportData?: Uint8Array }): QuoteGenerator {
  return (reportData) => {
    if (signed !== undefined) signed.reportData = reportData;
    return { format, report };
  };
}
