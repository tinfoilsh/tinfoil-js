/**
 * Test-time access to the shared tinfoil-conformance v3 vectors.
 *
 * The vectors directory (`vectors/v3` of a tinfoil-conformance checkout) is
 * taken from TINFOIL_CONFORMANCE_FIXTURES, the variable test/conformance.test.ts
 * and `npm run test:conformance` use. When the variable is unset, the sibling
 * checkout of the flywheel layout (`../../../tinfoil-conformance/vectors/v3`
 * from this package) is used if it exists. Suites that need the vectors wrap
 * themselves in `describe.skipIf(!conformanceAvailable())` and load their
 * material in `beforeAll`, so a missing checkout skips them instead of failing.
 *
 * Each vector is `{id, stage, input, expected}`; `input.document_b64` carries
 * the attestation document whose collateral the unit tests pick apart. The
 * accessors below return that material in the shapes the tests consume.
 * The block stages (`rfc3161/`, `approval-bundle/`) have no document; their
 * inputs are read directly with `inputBytes` and `trustedRootBytes`, and
 * `loadFixtures` reads a whole stage directory.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const CONFORMANCE_ENV = "TINFOIL_CONFORMANCE_FIXTURES";

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const DEFAULT_DIR = resolve(PACKAGE_ROOT, "../../../tinfoil-conformance/vectors/v3");

/** The directory the variable names (which must exist: a wrong path fails loudly rather than skipping every vector suite), else the default when present. */
function resolveDir(): string | undefined {
  const env = process.env[CONFORMANCE_ENV];
  if (env !== undefined && env !== "") {
    const dir = resolve(env);
    if (!existsSync(dir)) throw new Error(`${CONFORMANCE_ENV}=${env} names no directory`);
    return dir;
  }
  return existsSync(DEFAULT_DIR) ? DEFAULT_DIR : undefined;
}

/** The vectors directory in use, or undefined when neither the variable nor the default location names one. */
export const conformanceDir: string | undefined = resolveDir();

/** True when the vectors directory exists; suites that read vectors skip otherwise. */
export function conformanceAvailable(): boolean {
  return conformanceDir !== undefined && existsSync(conformanceDir);
}

/** A suite title that names what a skipped run is missing. */
export function vectorsTitle(title?: string): string {
  const what = "tinfoil-conformance vectors";
  return title === undefined ? what : `${title} (${what})`;
}

// ---------------------------------------------------------------- vectors

export interface FixtureInput {
  readonly schema_version?: string;
  readonly document_b64: string;
  readonly nonce_hex?: string;
  readonly repo?: string;
  readonly verification_time_unix?: number;
  readonly amd_root_ca_pem?: string;
  readonly ask_pem?: string;
  readonly intel_sgx_root_pem?: string;
  readonly sigstore_trusted_root_json_b64?: string;
  // v3-verify-timestamp
  readonly timestamp_response_b64?: string;
  readonly timestamp_input_b64?: string;
  // v3-authenticate-approval
  readonly bundle_json_b64?: string;
  readonly signing_keys_pem?: readonly string[];
  readonly artifact_digest_hex?: string;
  readonly [key: string]: unknown;
}

export interface ConformanceFixture {
  readonly id: string;
  readonly stage: string;
  readonly input: FixtureInput;
  readonly expected: { readonly accepted: boolean; readonly code?: string; readonly [key: string]: unknown };
}

export interface CollateralEntry {
  readonly id: string;
  readonly role?: string;
  readonly format: string;
  readonly subjects?: readonly string[];
  // The data shape depends on the format; accessors below narrow it.
  readonly data: any;
}

export interface ConformanceDocument {
  readonly format: string;
  readonly cpu_evidence: { readonly format: string; readonly report_base64: string; readonly [key: string]: unknown };
  readonly collateral: readonly CollateralEntry[];
  readonly [key: string]: unknown;
}

/** Reads and parses one vector by its path under the vectors directory, e.g. "golden/golden-happy.json". */
export function loadFixture(relPath: string): ConformanceFixture {
  if (!conformanceAvailable()) {
    throw new Error(`${vectorsTitle()} not available: set ${CONFORMANCE_ENV} to a tinfoil-conformance vectors/v3 directory`);
  }
  return JSON.parse(readFileSync(resolve(conformanceDir!, relPath), "utf8")) as ConformanceFixture;
}

/** Reads every vector of one stage directory, e.g. "rfc3161", in file-name order. */
export function loadFixtures(relDir: string): ConformanceFixture[] {
  if (!conformanceAvailable()) {
    throw new Error(`${vectorsTitle()} not available: set ${CONFORMANCE_ENV} to a tinfoil-conformance vectors/v3 directory`);
  }
  const dir = resolve(conformanceDir!, relDir);
  return readdirSync(dir)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map((name) => loadFixture(`${relDir}/${name}`));
}

const base64 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "base64"));
const base64Json = (s: string): unknown => JSON.parse(Buffer.from(s, "base64").toString("utf8"));

/** The bytes a base64 input member carries; the vector must have it. */
export function inputBytes(fixture: ConformanceFixture, member: string): Uint8Array {
  const value = fixture.input[member];
  if (typeof value !== "string") throw new Error(`${fixture.id}: input has no ${member}`);
  return base64(value);
}

/** The synthetic Sigstore trusted root of a vector as the JSON bytes parseTrustedRoot reads; undefined when the vector uses the embedded root. */
export function trustedRootBytes(fixture: ConformanceFixture): Uint8Array | undefined {
  const b64 = fixture.input.sigstore_trusted_root_json_b64;
  return b64 === undefined || b64 === "" ? undefined : base64(b64);
}

/** The attestation document of a vector, parsed. */
export function decodeDocument(fixture: ConformanceFixture): ConformanceDocument {
  return base64Json(fixture.input.document_b64) as ConformanceDocument;
}

/** `input.repo`; the vector must name one. */
export function repoOf(fixture: ConformanceFixture): string {
  if (fixture.input.repo === undefined) throw new Error(`${fixture.id}: input has no repo`);
  return fixture.input.repo;
}

/** `input.verification_time_unix`, undefined when the vector verifies at the wall clock. */
export function verificationTime(fixture: ConformanceFixture): number | undefined {
  return fixture.input.verification_time_unix;
}

/** The synthetic Sigstore trusted root of a vector, parsed; undefined when the bundles verify under the embedded root. */
export function syntheticTrustedRoot(fixture: ConformanceFixture): unknown {
  const b64 = fixture.input.sigstore_trusted_root_json_b64;
  return b64 === undefined ? undefined : base64Json(b64);
}

function entriesOf(doc: ConformanceDocument, pattern: RegExp): CollateralEntry[] {
  return doc.collateral.filter((c) => pattern.test(c.format));
}

function entryOf(doc: ConformanceDocument, what: string, pattern: RegExp): CollateralEntry {
  const matches = entriesOf(doc, pattern);
  if (matches.length !== 1) throw new Error(`document has ${matches.length} ${what} collateral entries, expected 1`);
  return matches[0]!;
}

// ---------------------------------------------------------------- sigstore

export interface SigstoreEntry {
  readonly id: string;
  readonly format: string;
  readonly data: { readonly repo?: string; readonly tag?: string; readonly digest?: string; readonly sigstore_bundle: unknown };
}

const SIGSTORE_FORMAT = /\/collateral\/sigstore-(code|platform|freshness)\/v1$/;

/** The sigstore-code, sigstore-platform and sigstore-freshness entries of a document, in document order. */
export function sigstoreCollateral(doc: ConformanceDocument): SigstoreEntry[] {
  return entriesOf(doc, SIGSTORE_FORMAT).map((c) => ({ id: c.id, format: c.format, data: c.data as SigstoreEntry["data"] }));
}

// ---------------------------------------------------------------- AMD

/** The AMD certificate material of a vector: the document's VCEK and CRL collateral and the roots the input names. */
export interface AmdMaterial {
  readonly verification_time_unix?: number;
  readonly root_pem?: string;
  readonly ask_pem?: string;
  readonly vcek_der_base64: string;
  readonly cert_chain_pem: string;
  readonly crl_der_base64: string;
}

export function amdMaterial(fixture: ConformanceFixture): AmdMaterial {
  const doc = decodeDocument(fixture);
  const vcek = entryOf(doc, "amd-vcek", /\/collateral\/amd-vcek\/v1$/).data as { vcek_der_base64: string; cert_chain_pem: string };
  const crl = entryOf(doc, "amd-crl", /\/collateral\/amd-crl\/v1$/).data as { crl_der_base64: string };
  return {
    ...(fixture.input.verification_time_unix !== undefined ? { verification_time_unix: fixture.input.verification_time_unix } : {}),
    ...(fixture.input.amd_root_ca_pem !== undefined ? { root_pem: fixture.input.amd_root_ca_pem } : {}),
    ...(fixture.input.ask_pem !== undefined ? { ask_pem: fixture.input.ask_pem } : {}),
    vcek_der_base64: vcek.vcek_der_base64,
    cert_chain_pem: vcek.cert_chain_pem,
    crl_der_base64: crl.crl_der_base64,
  };
}

// ---------------------------------------------------------------- Intel

export interface PcsResponse {
  readonly url: string;
  readonly headers?: Readonly<Record<string, readonly string[] | null>> | null;
  readonly body_base64: string;
}

/** The captured Intel PCS responses of a document. */
export function intelPcsResponses(doc: ConformanceDocument): readonly PcsResponse[] {
  return (entryOf(doc, "intel-pcs", /\/collateral\/intel-pcs\/v1$/).data as { responses: readonly PcsResponse[] }).responses;
}

/** The one captured response whose URL path matches. */
export function pcsResponse(responses: readonly PcsResponse[], path: RegExp): PcsResponse {
  const matches = responses.filter((r) => path.test(new URL(r.url).pathname));
  if (matches.length !== 1) throw new Error(`${matches.length} PCS responses match ${path}, expected 1`);
  return matches[0]!;
}

/** The first value of a PCS response header, URL-decoded as Intel delivers issuer chains. */
export function pcsHeader(response: PcsResponse, name: string): string {
  const values = response.headers?.[name];
  if (!values || values.length === 0) throw new Error(`PCS response ${response.url} has no ${name} header`);
  return decodeURIComponent(values[0]!);
}

/** The TDX quote bytes of a document. */
export function tdxQuoteBytes(doc: ConformanceDocument): Uint8Array {
  if (!/\/format\/tdx-quote\/v1$/.test(doc.cpu_evidence.format)) throw new Error(`cpu evidence is ${doc.cpu_evidence.format}, not a TDX quote`);
  return base64(doc.cpu_evidence.report_base64);
}

/**
 * The PCK certificate chain a TDX quote carries as its certification data
 * (type 5), PEM text leaf first. A v4 quote's certification data is wrapped
 * in the QE report certification data (type 6).
 */
export function pckCertChainPem(quote: Uint8Array): string {
  const view = new DataView(quote.buffer, quote.byteOffset, quote.byteLength);
  const u16 = (at: number): number => view.getUint16(at, true);
  const u32 = (at: number): number => view.getUint32(at, true);
  const version = u16(0);
  // Header (48 bytes), then the TD report: 584 bytes in v4, sized by the v5 body header.
  let at = version === 4 ? 48 + 584 : version === 5 ? 48 + 6 + u32(50) : -1;
  if (at < 0) throw new Error(`unsupported TDX quote version ${version}`);
  at += 4; // signature data length
  at += 64 + 64; // ECDSA signature, attestation public key
  let type = u16(at);
  let size = u32(at + 2);
  at += 6;
  if (type === 6) {
    at += 384 + 64; // QE report and its signature
    at += 2 + u16(at); // QE authentication data
    type = u16(at);
    size = u32(at + 2);
    at += 6;
  }
  if (type !== 5) throw new Error(`quote certification data is type ${type}, expected 5 (PCK certificate chain)`);
  if (at + size > quote.length) throw new Error("quote certification data overruns the quote");
  let end = at + size;
  while (end > at && quote[end - 1] === 0) end--; // some quoting enclaves NUL-terminate the PEM
  return new TextDecoder().decode(quote.subarray(at, end));
}

/** The Intel certificate material of a vector: the root the input names, the quote's PCK chain, and the CRLs the PCS collateral carries. */
export interface IntelMaterial {
  readonly verification_time_unix?: number;
  readonly root_pem: string;
  readonly pck_chain_pem: string;
  readonly pck_crl_der_base64: string;
  readonly pck_crl_issuer_chain_pem: string;
  readonly root_crl_der_base64: string;
}

export function intelMaterial(fixture: ConformanceFixture): IntelMaterial {
  if (fixture.input.intel_sgx_root_pem === undefined) throw new Error(`${fixture.id}: input has no intel_sgx_root_pem`);
  const doc = decodeDocument(fixture);
  const responses = intelPcsResponses(doc);
  const pckCrl = pcsResponse(responses, /\/pckcrl$/);
  const rootCrl = pcsResponse(responses, /\/(rootcacrl|IntelSGXRootCA\.der)$/);
  return {
    ...(fixture.input.verification_time_unix !== undefined ? { verification_time_unix: fixture.input.verification_time_unix } : {}),
    root_pem: fixture.input.intel_sgx_root_pem,
    pck_chain_pem: pckCertChainPem(tdxQuoteBytes(doc)),
    pck_crl_der_base64: pckCrl.body_base64,
    pck_crl_issuer_chain_pem: pcsHeader(pckCrl, "Sgx-Pck-Crl-Issuer-Chain"),
    root_crl_der_base64: rootCrl.body_base64,
  };
}
