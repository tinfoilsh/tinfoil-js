import { UsageError } from "./errors.js";
import {
  array,
  concat,
  fields,
  hex,
  nonempty,
  object,
  parseJSON,
  sha256,
  string,
  unbase64,
  unhex,
  utf8,
} from "./encoding.js";
import type { CryptoMaterialItem } from "./types.js";
export const NONCE_SIZE = 32;
/** @internal */
export const ATTESTATION_V3 = "https://tinfoil.sh/predicate/attestation/v3";
/** @internal */
export const REPORT_DATA_V1 = "https://tinfoil.sh/report-data/v1";
export const KEY_TLS = "https://tinfoil.sh/key/spki-fp-sha256/v1";
export const KEY_HPKE = "https://tinfoil.sh/key/x25519-hpke/v1";
/** @internal */
export const COLLATERALS_V2 =
  "https://tinfoil.sh/predicate/attestation-collaterals/v2";
/** @internal */
export const COLLATERALS_V3 =
  "https://tinfoil.sh/predicate/attestation-collaterals/v3";
/** @internal */
export const FORMAT = Object.freeze(
  Object.fromEntries(
    [
      "amd-vcek",
      "amd-crl",
      "intel-pcs",
      "sigstore-code",
      "sigstore-platform",
      "sigstore-freshness",
      "artifact-freshness",
      "config-endorsement",
      "config",
      "igvm-runtime",
    ].map((x) => [x, `https://tinfoil.sh/collateral/${x}/v1`]),
  ) as Record<string, string>,
);
/** @internal */
export interface CPUEndorsements {
  amdVcek?: { vcekDer: Uint8Array; certChainPem: string };
  amdCrl?: { crlDer: Uint8Array };
  intelPcs?: {
    responses: {
      url: string;
      body: Uint8Array;
      headers: Record<string, string[]>;
    }[];
  };
}
/** @internal */
export interface SigstoreReference {
  repo: string;
  tag: string;
  digest: string;
  bundle: unknown;
}
/** @internal */
export interface ConfigMaterial {
  config: Uint8Array;
  reference: string;
  bundle?: unknown;
}
/** @internal */
export interface RuntimeMaterial extends SigstoreReference {
  manifest: Uint8Array;
}
/** @internal */
export interface CollateralSet {
  cpu: CPUEndorsements;
  code?: SigstoreReference;
  platform?: SigstoreReference;
  config?: ConfigMaterial;
  runtime?: RuntimeMaterial;
  configPlatform?: SigstoreReference;
  platformCount: number;
  freshness: Map<string, { format: string; bundle: unknown }>;
}
/** @internal */
export interface ParsedDocument {
  evidence: { format: string; report: Uint8Array };
  expectedReportData: Uint8Array;
  cryptoMaterial: CryptoMaterialItem[];
  deviceEvidence: Record<string, any>[];
  collateralFormat: string;
  collateral: CollateralSet;
}
export function randomNonce(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(NONCE_SIZE));
}
/** @internal */
export async function computeReportData(
  nonce: Uint8Array,
  cryptoHash: Uint8Array,
  deviceHash: Uint8Array,
): Promise<Uint8Array> {
  if ([nonce, cryptoHash, deviceHash].some((b) => b.length !== 32))
    throw new UsageError("REPORT_DATA inputs must each be 32 bytes");
  return concat(
    await sha256(concat(utf8(REPORT_DATA_V1), nonce, cryptoHash, deviceHash)),
    new Uint8Array(32),
  );
}
function bundle(v: unknown): unknown {
  if (v === undefined || v === null) throw new Error("Missing sigstore_bundle");
  return v;
}
function ref(v: unknown): SigstoreReference {
  const d = fields(
    v,
    ["repo", "tag", "digest", "sigstore_bundle"],
    ["digest", "sigstore_bundle"],
  );
  return {
    repo: d.repo === undefined ? "" : string(d.repo),
    tag: d.tag === undefined ? "" : string(d.tag),
    digest: nonempty(d.digest),
    bundle: bundle(d.sigstore_bundle),
  };
}
function config(v: unknown, signed: boolean): ConfigMaterial {
  const d = fields(
    v,
    ["endorsement_ref", "config_base64", "sigstore_bundle"],
    ["config_base64"],
  );
  const b = unbase64(d.config_base64);
  if (!b.length) throw new Error("Empty config");
  if (signed) {
    if (
      typeof d.endorsement_ref !== "string" ||
      !/^sha256:[0-9a-f]{64}$/.test(d.endorsement_ref)
    )
      throw new Error("Invalid endorsement reference");
    object(d.sigstore_bundle);
  } else if (d.endorsement_ref !== undefined || d.sigstore_bundle !== undefined)
    throw new Error("Plain config contains endorsement");
  return {
    config: b,
    reference: d.endorsement_ref ?? "",
    bundle: d.sigstore_bundle,
  };
}
/** @internal */
export function decodeCollateral(entries: unknown): CollateralSet {
  const out: CollateralSet = {
    cpu: {},
    platformCount: 0,
    freshness: new Map(),
  };
  const seen = new Set<string>();
  for (const v of array(entries, "collateral")) {
    const e = fields(
      v,
      ["id", "role", "format", "subjects", "data"],
      ["id", "role", "format", "data"],
    );
    const id = nonempty(e.id),
      format = nonempty(e.format);
    if (seen.has(id)) throw new Error("Duplicate collateral id");
    seen.add(id);
    if (e.role !== "endorsement" && e.role !== "reference-values")
      throw new Error("Unknown collateral role");
    object(e.data);
    let cpu = false;
    if (e.subjects !== undefined) {
      const subjects = array(e.subjects);
      for (const s of subjects) nonempty(s);
      if (new Set(subjects).size !== subjects.length)
        throw new Error("Duplicate collateral subject");
      cpu = subjects.includes("cpu");
    }
    if (id === "platform" || format === FORMAT["sigstore-platform"])
      out.platformCount++;
    if (
      id === "tinfoil-config" ||
      format === FORMAT["config-endorsement"] ||
      format === FORMAT.config
    ) {
      if (
        id !== "tinfoil-config" ||
        ![FORMAT.config, FORMAT["config-endorsement"]].includes(format) ||
        e.role !== "reference-values"
      )
        throw new Error("Conflicting config collateral");
      out.config = config(e.data, format === FORMAT["config-endorsement"]);
      continue;
    }
    if (id === "runtime" || format === FORMAT["igvm-runtime"]) {
      if (
        id !== "runtime" ||
        format !== FORMAT["igvm-runtime"] ||
        e.role !== "reference-values"
      )
        throw new Error("Conflicting runtime collateral");
      const d = fields(e.data, [
        "repo",
        "tag",
        "digest",
        "manifest_base64",
        "sigstore_bundle",
      ]);
      if (
        d.repo !== "tinfoilsh/cvmimage" ||
        !/^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(
          string(d.tag),
        )
      )
        throw new Error("Invalid runtime reference");
      unhex(d.digest, 32);
      object(d.sigstore_bundle);
      out.runtime = {
        repo: d.repo,
        tag: d.tag,
        digest: d.digest,
        manifest: unbase64(d.manifest_base64),
        bundle: d.sigstore_bundle,
      };
      continue;
    }
    if (format === FORMAT["artifact-freshness"] || id === "runtime-freshness") {
      if (
        !["runtime-freshness", "platform-freshness"].includes(id) ||
        format !== FORMAT["artifact-freshness"] ||
        e.role !== "reference-values"
      )
        throw new Error("Conflicting artifact freshness");
      const d = fields(e.data, ["sigstore_bundle"]);
      out.freshness.set(id, { format, bundle: bundle(d.sigstore_bundle) });
      continue;
    }
    if (e.role === "endorsement") {
      if (format === FORMAT["amd-vcek"]) {
        const d = fields(e.data, ["vcek_der_base64", "cert_chain_pem"], []);
        const value = {
          vcekDer: unbase64(d.vcek_der_base64 ?? ""),
          certChainPem: string(d.cert_chain_pem ?? ""),
        };
        if (cpu && !out.cpu.amdVcek) out.cpu.amdVcek = value;
      }
      if (format === FORMAT["amd-crl"]) {
        const d = fields(e.data, ["crl_der_base64"], []);
        const value = { crlDer: unbase64(d.crl_der_base64 ?? "") };
        if (cpu && !out.cpu.amdCrl) out.cpu.amdCrl = value;
      }
      if (format === FORMAT["intel-pcs"]) {
        const d = fields(e.data, ["responses"], []);
        const responses = array(d.responses ?? []).map((v) => {
          const r = fields(v, ["url", "headers", "body_base64"], []);
          const headers = object(r.headers ?? {});
          for (const v of Object.values(headers))
            for (const s of array(v)) string(s);
          return {
            url: string(r.url ?? ""),
            headers: headers as Record<string, string[]>,
            body: unbase64(r.body_base64 ?? ""),
          };
        });
        if (cpu && !out.cpu.intelPcs) out.cpu.intelPcs = { responses };
      }
    } else if (format === FORMAT["sigstore-code"]) {
      const r = ref(e.data);
      out.code ??= r;
    } else if (format === FORMAT["sigstore-platform"]) {
      const r = ref(e.data);
      out.platform ??= r;
      if (id === "platform") out.configPlatform = r;
    } else if (format === FORMAT["sigstore-freshness"]) {
      const d = fields(e.data, ["sigstore_bundle"]);
      out.freshness.set(id, { format, bundle: bundle(d.sigstore_bundle) });
    }
  }
  return out;
}
async function decodeDocument(
  bytes: Uint8Array,
  expectedNonce: Uint8Array,
  bind: boolean,
): Promise<ParsedDocument> {
  if (
    !(expectedNonce instanceof Uint8Array) ||
    expectedNonce.length !== NONCE_SIZE
  )
    throw new UsageError("Expected nonce must contain 32 bytes");
  if (!(bytes instanceof Uint8Array))
    throw new UsageError("Document must be bytes");
  const d = fields(
    parseJSON(bytes),
    [
      "format",
      "challenge",
      "cpu_evidence",
      "crypto_material",
      "device_evidence",
      "collateral_format",
      "collateral",
    ],
    [
      "format",
      "challenge",
      "cpu_evidence",
      "crypto_material",
      "device_evidence",
      "collateral",
    ],
  );
  if (d.format !== ATTESTATION_V3)
    throw new Error("Unsupported attestation format");
  const c = fields(d.challenge, [
    "nonce",
    "report_data",
    "report_data_algorithm",
  ]);
  unhex(c.nonce, 32);
  unhex(c.report_data, 64);
  if (
    c.report_data_algorithm !== REPORT_DATA_V1 ||
    (bind && c.nonce !== hex(expectedNonce))
  )
    throw new Error("Challenge does not match caller nonce");
  const e = fields(d.cpu_evidence, ["format", "report_base64", "endorsed"]);
  nonempty(e.format);
  const report = unbase64(nonempty(e.report_base64));
  const endorsed = fields(e.endorsed, [
    "crypto_material_hash",
    "device_evidence_hash",
  ]);
  unhex(endorsed.crypto_material_hash, 32);
  unhex(endorsed.device_evidence_hash, 32);
  const cb = unbase64(nonempty(d.crypto_material)),
    db = unbase64(nonempty(d.device_evidence));
  const cm = fields(parseJSON(cb), ["format", "items"]),
    de = fields(parseJSON(db), ["format", "items"]);
  if (
    cm.format !== "https://tinfoil.sh/crypto-material/v1" ||
    de.format !== "https://tinfoil.sh/device-evidence/v1"
  )
    throw new Error("Unsupported endorsed section format");
  const seen = new Set<string>();
  const items = array(cm.items).map((v) => {
    const i = fields(v, ["id", "format", "data"]);
    const id = nonempty(i.id),
      format = nonempty(i.format);
    if (seen.has(id)) throw new Error("Duplicate crypto material id");
    seen.add(id);
    unhex(i.data, [KEY_TLS, KEY_HPKE].includes(format) ? 32 : undefined);
    return { id, format, data: i.data };
  });
  seen.clear();
  const devices = array(de.items).map((v) => {
    const i = fields(v, ["id", "kind", "vendor", "format", "evidence"]);
    nonempty(i.id);
    if (i.id === "cpu") throw new Error("Device id cpu is reserved");
    object(i.evidence, "device evidence");
    if (seen.has(i.id)) throw new Error("Duplicate device evidence id");
    seen.add(i.id);
    for (const k of ["kind", "vendor", "format"]) nonempty(i[k]);
    return i;
  });
  const ch = await sha256(cb),
    dh = await sha256(db);
  if (
    bind &&
    (hex(ch) !== endorsed.crypto_material_hash ||
      hex(dh) !== endorsed.device_evidence_hash)
  )
    throw new Error("Endorsed section hash mismatch");
  const expectedReportData = await computeReportData(expectedNonce, ch, dh);
  if (bind && hex(expectedReportData) !== c.report_data)
    throw new Error("REPORT_DATA mismatch");
  const collateralFormat =
    d.collateral_format === undefined || d.collateral_format === ""
      ? COLLATERALS_V2
      : string(d.collateral_format);
  if (![COLLATERALS_V2, COLLATERALS_V3].includes(collateralFormat))
    throw new Error("Unsupported collateral profile");
  const collateral = decodeCollateral(d.collateral);
  if (
    collateralFormat === COLLATERALS_V3
      ? !!collateral.code
      : !!(collateral.config || collateral.runtime)
  )
    throw new Error("Collateral entries conflict with selected profile");
  for (const f of collateral.freshness.values())
    if (
      (collateralFormat === COLLATERALS_V3) !==
      (f.format === FORMAT["artifact-freshness"])
    )
      throw new Error("Freshness collateral conflicts with selected profile");
  return {
    evidence: { format: e.format, report },
    expectedReportData,
    cryptoMaterial: items,
    deviceEvidence: devices,
    collateralFormat,
    collateral,
  };
}

/** @internal */
export function parseDocument(
  bytes: Uint8Array,
  nonce: Uint8Array,
): Promise<ParsedDocument> {
  return decodeDocument(bytes, nonce, true);
}
/** @internal Private structural stage for the conformance adapter; it authenticates nothing. */
export function decodeDocumentForConformance(
  bytes: Uint8Array,
): Promise<ParsedDocument> {
  return decodeDocument(bytes, new Uint8Array(32), false);
}
