/**
 * The document's collateral array: untrusted transport for vendor
 * endorsements, reference values and freshness proofs. Every entry is
 * authenticated by its own signature chain later; decoding only checks shape.
 */
import { arr, object, raw, str } from "../../internal/json/decode.js";
import { JsonError, type JsonObject, type JsonValue } from "../../internal/json/index.js";
import { decodeConfigEndorsement, type ConfigEndorsement } from "./config.js";
import { decodeRuntime, PLATFORM_ID, RUNTIME_ID, RUNTIME_V1_FORMAT, type RuntimeCollateral } from "./runtime.js";
import { decodeAmdCrl, decodeAmdVcek, type AmdCrl, type AmdVcek } from "./sev.js";
import { decodeFreshness, decodeSigstoreRef, type Freshness, type SigstoreRef } from "./sigstore.js";
import { decodeIntelPcs, type IntelPcs } from "./tdx.js";

export const FORMAT_V2 = "https://tinfoil.sh/predicate/attestation-collaterals/v2";
export const FORMAT_V3 = "https://tinfoil.sh/predicate/attestation-collaterals/v3";
export const AMD_VCEK_V1_FORMAT = "https://tinfoil.sh/collateral/amd-vcek/v1";
export const AMD_CRL_V1_FORMAT = "https://tinfoil.sh/collateral/amd-crl/v1";
export const INTEL_PCS_V1_FORMAT = "https://tinfoil.sh/collateral/intel-pcs/v1";
export const NVIDIA_GPU_V1_FORMAT = "https://tinfoil.sh/collateral/nvidia-gpu/v1";
export const SIGSTORE_CODE_V1_FORMAT = "https://tinfoil.sh/collateral/sigstore-code/v1";
export const SIGSTORE_PLATFORM_V1_FORMAT = "https://tinfoil.sh/collateral/sigstore-platform/v1";
export const SIGSTORE_FRESHNESS_V1_FORMAT = "https://tinfoil.sh/collateral/sigstore-freshness/v1";
export const ARTIFACT_FRESHNESS_V1_FORMAT = "https://tinfoil.sh/collateral/artifact-freshness/v1";
export const CONFIG_ENDORSEMENT_V1_FORMAT = "https://tinfoil.sh/collateral/config-endorsement/v1";
/** A config endorsement that may carry a registry issuer certificate and omit the config bytes. */
export const CONFIG_ENDORSEMENT_V2_FORMAT = "https://tinfoil.sh/collateral/config-endorsement/v2";
export const CONFIG_V1_FORMAT = "https://tinfoil.sh/collateral/config/v1";

export const ROLE_ENDORSEMENT = "endorsement";
export const ROLE_REFERENCE_VALUES = "reference-values";

export const SUBJECT_CPU = "cpu";
export const FRESHNESS_ID_CODE = "code-freshness";
export const FRESHNESS_ID_PLATFORM = "platform-freshness";
export const FRESHNESS_ID_RUNTIME = "runtime-freshness";
export const CONFIG_ID = "tinfoil-config";

/** One wire collateral record. `data` stays undecoded until its format is known; undefined when absent. */
export interface Entry {
  readonly id: string;
  readonly role: string;
  readonly format: string;
  readonly subjects?: readonly string[];
  readonly data: JsonValue | undefined;
}

/** Thrown (or wrapped) when a required collateral entry is absent. */
export class NotFoundError extends Error {
  constructor(what: string) {
    super(`collateral entry not found: ${what}`);
    this.name = "NotFoundError";
  }
}

/** Vendor collateral for the reserved "cpu" subject. */
export interface CpuEndorsements {
  readonly amdVcek?: AmdVcek;
  readonly amdCrl?: AmdCrl;
  readonly intelPcs?: IntelPcs;
}

/** Decoded collateral: the first entry per purpose, freshness by id. */
export interface CollateralSet {
  readonly cpu: CpuEndorsements;
  readonly sigstoreCode?: SigstoreRef;
  readonly sigstorePlatform?: SigstoreRef;
  readonly config?: ConfigEndorsement;
  readonly runtime?: RuntimeCollateral;
  readonly freshness: ReadonlyMap<string, Freshness>;
  /** @internal for configPlatform(): platform entries seen, and the one with id "platform". */
  readonly platformCount: number;
  readonly configPlatform?: SigstoreRef;
}

/**
 * Decodes the wire array into entries; an entry with a member outside the
 * known set rejects. null decodes as no entries.
 */
export function decodeEntries(v: JsonValue | undefined): Entry[] {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) throw new JsonError("collateral must be an array");
  return v.map((item: JsonValue) => {
    const o = object(item, "collateral entry", ["id", "role", "format", "subjects", "data"]);
    const subjects = arr(o, "subjects")?.map((s) => {
      if (s === null) return "";
      if (typeof s !== "string") throw new JsonError("collateral subjects must be strings");
      return s;
    });
    return { id: str(o, "id"), role: str(o, "role"), format: str(o, "format"), subjects, data: raw(o, "data") };
  });
}

/**
 * Validates every entry's shape, decodes known role+format pairs, and
 * enforces reserved ids. An entry with no decoder for its role and format is
 * shape-checked and dropped. An endorsement entry serves the CPU only when its
 * subjects include "cpu".
 */
const CONFIG_FORMATS: readonly string[] = [CONFIG_ENDORSEMENT_V1_FORMAT, CONFIG_ENDORSEMENT_V2_FORMAT, CONFIG_V1_FORMAT];

export function decode(entries: readonly Entry[]): CollateralSet {
  validate(entries);
  const cpu: { amdVcek?: AmdVcek; amdCrl?: AmdCrl; intelPcs?: IntelPcs } = {};
  const freshness = new Map<string, Freshness>();
  let sigstoreCode: SigstoreRef | undefined;
  let sigstorePlatform: SigstoreRef | undefined;
  let config: ConfigEndorsement | undefined;
  let runtime: RuntimeCollateral | undefined;
  let configPlatform: SigstoreRef | undefined;
  let platformCount = 0;

  for (const entry of entries) {
    const forCpu = entry.subjects?.includes(SUBJECT_CPU) ?? false;
    if (entry.id === PLATFORM_ID || entry.format === SIGSTORE_PLATFORM_V1_FORMAT) platformCount++;

    if (entry.id === CONFIG_ID || CONFIG_FORMATS.includes(entry.format)) {
      if (entry.id !== CONFIG_ID || !CONFIG_FORMATS.includes(entry.format) || entry.role !== ROLE_REFERENCE_VALUES) {
        throw new Error(`conflicting collateral entry for "${CONFIG_ID}"`);
      }
      config = decodeConfigEndorsement(entry);
    } else if (entry.id === RUNTIME_ID || entry.format === RUNTIME_V1_FORMAT) {
      if (entry.id !== RUNTIME_ID || entry.format !== RUNTIME_V1_FORMAT || entry.role !== ROLE_REFERENCE_VALUES) {
        throw new Error(`conflicting collateral entry for "${RUNTIME_ID}"`);
      }
      runtime = decodeRuntime(entry);
    } else if (entry.format === ARTIFACT_FRESHNESS_V1_FORMAT || entry.id === FRESHNESS_ID_RUNTIME) {
      if (
        (entry.id !== FRESHNESS_ID_PLATFORM && entry.id !== FRESHNESS_ID_RUNTIME) ||
        entry.format !== ARTIFACT_FRESHNESS_V1_FORMAT ||
        entry.role !== ROLE_REFERENCE_VALUES
      ) {
        throw new Error(`conflicting artifact freshness collateral "${entry.id}"`);
      }
      freshness.set(entry.id, decodeFreshness(entry));
    } else if (entry.role === ROLE_ENDORSEMENT && entry.format === AMD_VCEK_V1_FORMAT) {
      const v = decodeAmdVcek(entry);
      if (forCpu && cpu.amdVcek === undefined) cpu.amdVcek = v;
    } else if (entry.role === ROLE_ENDORSEMENT && entry.format === AMD_CRL_V1_FORMAT) {
      const v = decodeAmdCrl(entry);
      if (forCpu && cpu.amdCrl === undefined) cpu.amdCrl = v;
    } else if (entry.role === ROLE_ENDORSEMENT && entry.format === INTEL_PCS_V1_FORMAT) {
      const v = decodeIntelPcs(entry);
      if (forCpu && cpu.intelPcs === undefined) cpu.intelPcs = v;
    } else if (entry.role === ROLE_REFERENCE_VALUES && entry.format === SIGSTORE_CODE_V1_FORMAT) {
      const v = decodeSigstoreRef(entry);
      sigstoreCode ??= v;
    } else if (entry.role === ROLE_REFERENCE_VALUES && entry.format === SIGSTORE_PLATFORM_V1_FORMAT) {
      const v = decodeSigstoreRef(entry);
      sigstorePlatform ??= v;
      if (entry.id === PLATFORM_ID) configPlatform = v;
    } else if (entry.role === ROLE_REFERENCE_VALUES && entry.format === SIGSTORE_FRESHNESS_V1_FORMAT) {
      // validate already rejected duplicate ids.
      freshness.set(entry.id, decodeFreshness(entry));
    }
  }
  return { cpu, sigstoreCode, sigstorePlatform, config, runtime, freshness, platformCount, configPlatform };
}

function validate(entries: readonly Entry[]): void {
  const seen = new Set<string>();
  entries.forEach((entry, i) => {
    if (entry.id === "" || entry.format === "") throw new Error(`collateral entry ${i} is incomplete`);
    if (seen.has(entry.id)) throw new Error(`duplicate collateral entry id "${entry.id}"`);
    seen.add(entry.id);
    if (entry.role !== ROLE_ENDORSEMENT && entry.role !== ROLE_REFERENCE_VALUES) {
      throw new Error(`collateral entry "${entry.id}" has unknown role "${entry.role}"`);
    }
    // Every entry's data must be exactly one JSON object, known format or not.
    if (!(entry.data instanceof Map)) {
      throw new Error(`collateral entry "${entry.id}" data is not a valid JSON object`);
    }
  });
}

/**
 * Strictly decodes an entry's data object with the given member set (any
 * other member rejects) and reads its fields with `read`. Any shape or type
 * error from either step carries the entry's context.
 */
export function unmarshalData<T>(entry: Entry, label: string, known: readonly string[], read: (data: JsonObject) => T): T {
  try {
    return read(object(entry.data ?? null, `${label} data`, known));
  } catch (err) {
    throw new Error(`parsing ${label} collateral entry "${entry.id}": ${(err as Error).message}`);
  }
}

/** The single config-platform reference (id "platform"). */
export function configPlatform(set: CollateralSet): SigstoreRef {
  if (set.platformCount === 0) throw new NotFoundError("no platform reference-values entry");
  if (set.platformCount !== 1 || set.configPlatform === undefined) {
    throw new Error("conflicting platform collateral for config verification");
  }
  return set.configPlatform;
}
