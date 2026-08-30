// What a verified quote is appraised against (Go: verifier/policy): which
// machines are endorsed, which platform configurations they may run, and
// the policy each must satisfy. Inputs must come from a verified
// reference-values source; the module itself performs no cryptography.
//
// Parsing is fail-closed: unknown members, malformed identifiers, dangling
// references, or platform mismatches are errors. A policy that cannot be
// fully enforced is never partially applied.
//
// Layer attribution mirrors the Go verification flow: parseArtifact runs
// inside platform-endorsements authentication (PROVENANCE_REJECTED);
// policyFor / resolvePlatformMeasurement run inside policy assembly
// (POLICY_REJECTED).

import { decodeHex } from "./bytes.js";
import { VerificationError } from "./errors.js";
import {
  arrayOf,
  bool,
  field,
  int64Schema,
  intSchema,
  mapOf,
  optStructOf,
  str,
  structOf,
  uintSchema,
  unmarshal,
  type Schema,
} from "./strictjson.js";

// ArtifactFormat is the required format URI of the artifact.
export const ArtifactFormat = "https://tinfoil.sh/predicate/platform-endorsements/v1";

// PlatformSEVSNP labels AMD SEV-SNP policies.
export const PlatformSEVSNP = "sev-snp";
// PlatformTDX labels Intel TDX policies.
export const PlatformTDX = "tdx";

const sevIdentifierHexLen = 128;
const tdxIdentifierHexLen = 32;

const lowerHexRE = /^[0-9a-f]+$/;

// Shape is the canonical VM shape descriptor: the launch dimensions that
// determine a platform measurement. disks counts every attached disk
// (root, config, external config, one per model). gpus is undefined when
// the dimension is unknown for a measured slug; a code artifact always
// declares it.
export interface Shape {
  cpus: number;
  memoryMB: number;
  gpus?: number;
  disks: number;
}

// shapeSatisfies reports whether a measured slug shape satisfies the shape a
// code artifact requires. gpus is compared only when the slug declares it.
export function shapeSatisfies(s: Shape | undefined, required: Shape | undefined): boolean {
  if (s === undefined || required === undefined) return false;
  if (s.cpus !== required.cpus || s.memoryMB !== required.memoryMB || s.disks !== required.disks) {
    return false;
  }
  if (s.gpus !== undefined && required.gpus !== undefined && s.gpus !== required.gpus) {
    return false;
  }
  return true;
}

// Stack identifies the host software that produced a measurement.
export interface Stack {
  qemu: string;
  ovmf: string;
}

// PlatformMeasurement is one TDX platform configuration's expected
// registers, annotated with the VM shape it was measured for and,
// optionally, the host stack that produced it.
export interface PlatformMeasurement {
  mrtd: string;
  rtmr0: string;
  shape?: Shape;
  // stack is informational and never checked.
  stack?: Stack;
}

// TCB holds AMD security patch levels. fmcSpl applies to family 1Ah (Turin)
// parts only; it is required for Turin policies and invalid for Genoa.
export interface TCB {
  fmcSpl?: number;
  blSpl?: number;
  teeSpl?: number;
  snpSpl?: number;
  ucodeSpl?: number;
}

// GuestPolicy mirrors the SNP guest policy bits enforced at verification.
// All bits are compared: a bit absent from the policy JSON is false and the
// report must have it clear.
export interface GuestPolicy {
  debug: boolean;
  smt: boolean;
  migrateMA: boolean;
  singleSocket: boolean;
  cxlAllowed: boolean;
  memAES256XTS: boolean;
  raplDis: boolean;
  ciphertextHidingDRAM: boolean;
  pageSwapDisable: boolean;
}

// SNPPlatform mirrors the SNP PLATFORM_INFO expectations. All fields are
// compared by strict equality against the report, so machines with
// different host configurations need distinct policies.
export interface SNPPlatform {
  smtEnabled: boolean;
  tsmeEnabled: boolean;
  eccEnabled: boolean;
  raplDisabled: boolean;
  ciphertextHidingDRAM: boolean;
  aliasCheckComplete: boolean;
  tioEnabled: boolean;
  // iommuWriteSafe is PLATFORM_INFO bit 6 (Turin). It is required for Turin
  // policies and invalid for Genoa, enforced at policy assembly.
  iommuWriteSafe: boolean;
}

// SEVSNPPolicy is the standard SEV-SNP policy block. Every field is
// required and checked; there are no unchecked report fields. Numeric
// members are undefined when absent so parsing can tell an absent member
// from a meaningful zero — validation rejects any absent member.
export interface SEVSNPPolicy {
  minimumBuild?: number;
  // minimumAPIVersion floors the firmware version; minimumABIVersion
  // floors the guest policy's ABI version (both maj.min).
  minimumAPIVersion: string;
  minimumABIVersion: string;
  minimumGuestSVN?: number;
  minimumTCB: TCB;
  minimumLaunchTCB: TCB;
  guestPolicy: GuestPolicy;
  platformInfo: SNPPlatform;
  permitProvisionalFirmware: boolean;
  vmpl?: number;
  hostData: string;
  imageID: string;
  familyID: string;
  requireAuthorKey: boolean;
  requireIDBlock: boolean;
  minimumLaunchMitigationVector?: number;
  minimumCurrentMitigationVector?: number;
}

// TDXPolicy is the standard Intel TDX policy block. platformMeasurements
// names the measurements-map entries the machine is endorsed to run; the
// quote's own MRTD/RTMR0 select exactly one of them at policy assembly.
export interface TDXPolicy {
  qeVendorID: string;
  minimumTEETCBSVN: string;
  mrSeam: string;
  tdAttributes: string;
  xfam: string;
  minimumTCBEvaluationDataNumber?: number;
  platformMeasurements?: string[];
}

// Policy is a named appraisal policy. Exactly one platform block is set,
// matching platform.
export interface Policy {
  platform: string;
  sevSnp?: SEVSNPPolicy;
  tdx?: TDXPolicy;
}

// Artifact is the parsed policy document: named platform measurements,
// named policies, and the machines map keying both by hardware identity.
// machines maps a machine's hardware identifier to its policy name: SEV-SNP
// machines are keyed by the 64-byte CHIP_ID (128 lowercase hex chars), TDX
// machines by the 16-byte PPID (32 lowercase hex chars).
export interface Artifact {
  format: string;
  measurements: Map<string, PlatformMeasurement>;
  machines: Map<string, string>;
  policies: Map<string, Policy>;
}

const tcbSchema: Schema = structOf({
  fmc_spl: field("fmcSpl", uintSchema(8, true)),
  bl_spl: field("blSpl", uintSchema(8, true)),
  tee_spl: field("teeSpl", uintSchema(8, true)),
  snp_spl: field("snpSpl", uintSchema(8, true)),
  ucode_spl: field("ucodeSpl", uintSchema(8, true)),
});

const artifactSchema: Schema = structOf({
  format: field("format", str),
  measurements: field(
    "measurements",
    mapOf(
      structOf({
        mrtd: field("mrtd", str),
        rtmr0: field("rtmr0", str),
        shape: field(
          "shape",
          optStructOf({
            cpus: field("cpus", intSchema()),
            memory_mb: field("memoryMB", intSchema()),
            gpus: field("gpus", intSchema(true)),
            disks: field("disks", intSchema()),
          }),
        ),
        stack: field(
          "stack",
          optStructOf({
            qemu: field("qemu", str),
            ovmf: field("ovmf", str),
          }),
        ),
      }),
    ),
  ),
  machines: field("machines", mapOf(str)),
  policies: field(
    "policies",
    mapOf(
      structOf({
        platform: field("platform", str),
        sev_snp: field(
          "sevSnp",
          optStructOf({
            minimum_build: field("minimumBuild", uintSchema(8, true)),
            minimum_api_version: field("minimumAPIVersion", str),
            minimum_abi_version: field("minimumABIVersion", str),
            minimum_guest_svn: field("minimumGuestSVN", uintSchema(32, true)),
            minimum_tcb: field("minimumTCB", tcbSchema),
            minimum_launch_tcb: field("minimumLaunchTCB", tcbSchema),
            guest_policy: field(
              "guestPolicy",
              structOf({
                debug: field("debug", bool),
                smt: field("smt", bool),
                migrate_ma: field("migrateMA", bool),
                single_socket: field("singleSocket", bool),
                cxl_allowed: field("cxlAllowed", bool),
                mem_aes256_xts: field("memAES256XTS", bool),
                rapl_dis: field("raplDis", bool),
                ciphertext_hiding_dram: field("ciphertextHidingDRAM", bool),
                page_swap_disable: field("pageSwapDisable", bool),
              }),
            ),
            platform_info: field(
              "platformInfo",
              structOf({
                smt_enabled: field("smtEnabled", bool),
                tsme_enabled: field("tsmeEnabled", bool),
                ecc_enabled: field("eccEnabled", bool),
                rapl_disabled: field("raplDisabled", bool),
                ciphertext_hiding_dram: field("ciphertextHidingDRAM", bool),
                alias_check_complete: field("aliasCheckComplete", bool),
                tio_enabled: field("tioEnabled", bool),
                iommu_write_safe: field("iommuWriteSafe", bool),
              }),
            ),
            permit_provisional_firmware: field("permitProvisionalFirmware", bool),
            vmpl: field("vmpl", intSchema(true)),
            host_data: field("hostData", str),
            image_id: field("imageID", str),
            family_id: field("familyID", str),
            require_author_key: field("requireAuthorKey", bool),
            require_id_block: field("requireIDBlock", bool),
            minimum_launch_mitigation_vector: field("minimumLaunchMitigationVector", uintSchema(64, true)),
            minimum_current_mitigation_vector: field("minimumCurrentMitigationVector", uintSchema(64, true)),
          }),
        ),
        tdx: field(
          "tdx",
          optStructOf({
            qe_vendor_id: field("qeVendorID", str),
            minimum_tee_tcb_svn: field("minimumTEETCBSVN", str),
            mr_seam: field("mrSeam", str),
            td_attributes: field("tdAttributes", str),
            xfam: field("xfam", str),
            // int64 kept as an exact bigint so a floor above 2^53 stays
            // bit-exact (C1); the field shares no schema with the number-typed
            // vmpl / shape dimensions, which must remain plain numbers.
            minimum_tcb_evaluation_data_number: field("minimumTCBEvaluationDataNumber", int64Schema(true)),
            platform_measurements: field("platformMeasurements", arrayOf(str)),
          }),
        ),
      }),
    ),
  ),
});

// parseArtifact strictly decodes and validates a policy artifact (Go:
// policy.Parse). Unknown members anywhere in the document are rejected
// case-sensitively, as are duplicate member names.
export function parseArtifact(artifactJSON: Uint8Array): Artifact {
  let a: Artifact;
  try {
    a = unmarshal(artifactJSON, artifactSchema) as Artifact;
  } catch (err) {
    throw provenanceError(`parsing policy artifact: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (a.format !== ArtifactFormat) {
    throw provenanceError(`unsupported artifact format ${JSON.stringify(a.format)}`);
  }
  validateArtifact(a);
  return a;
}

function provenanceError(message: string): VerificationError {
  return new VerificationError("PROVENANCE_REJECTED", message);
}

function policyError(message: string): VerificationError {
  return new VerificationError("POLICY_REJECTED", message);
}

function validateArtifact(a: Artifact): void {
  for (const [name, p] of a.policies) {
    switch (p.platform) {
      case PlatformSEVSNP: {
        if (p.sevSnp === undefined || p.tdx !== undefined) {
          throw provenanceError(`policy ${JSON.stringify(name)}: platform sev-snp requires exactly the sev_snp block`);
        }
        const err = validateSEVSNPPolicy(p.sevSnp);
        if (err !== undefined) throw provenanceError(`policy ${JSON.stringify(name)}: ${err}`);
        break;
      }
      case PlatformTDX: {
        if (p.tdx === undefined || p.sevSnp !== undefined) {
          throw provenanceError(`policy ${JSON.stringify(name)}: platform tdx requires exactly the tdx block`);
        }
        const err = validateTDXPolicy(p.tdx);
        if (err !== undefined) throw provenanceError(`policy ${JSON.stringify(name)}: ${err}`);
        for (const ref of p.tdx.platformMeasurements ?? []) {
          if (!a.measurements.has(ref)) {
            throw provenanceError(
              `policy ${JSON.stringify(name)}: platform_measurements ref ${JSON.stringify(ref)} not in measurements`,
            );
          }
        }
        break;
      }
      default:
        throw provenanceError(`policy ${JSON.stringify(name)}: unsupported platform ${JSON.stringify(p.platform)}`);
    }
  }

  for (const [name, m] of a.measurements) {
    if (m.shape === undefined) {
      throw provenanceError(`measurement ${JSON.stringify(name)}: shape is required`);
    }
  }

  for (const [identifier, policyName] of a.machines) {
    const p = a.policies.get(policyName);
    if (p === undefined) {
      throw provenanceError(`machine ${truncID(identifier)}...: unknown policy ${JSON.stringify(policyName)}`);
    }
    if (!lowerHexRE.test(identifier)) {
      throw provenanceError(`machine ${truncID(identifier)}...: identifier is not lowercase hex`);
    }
    switch (p.platform) {
      case PlatformSEVSNP:
        if (identifier.length !== sevIdentifierHexLen) {
          throw provenanceError(
            `machine ${truncID(identifier)}...: sev-snp identifier must be ${sevIdentifierHexLen} hex chars, got ${identifier.length}`,
          );
        }
        break;
      case PlatformTDX:
        if (identifier.length !== tdxIdentifierHexLen) {
          throw provenanceError(
            `machine ${truncID(identifier)}...: tdx identifier must be ${tdxIdentifierHexLen} hex chars, got ${identifier.length}`,
          );
        }
        break;
    }
  }
}

// validateSEVSNPPolicy rejects a block with any absent required member or an
// unsupported setting (Go: SEVSNPPolicy.Validate). Returns an error string,
// or undefined when valid.
export function validateSEVSNPPolicy(p: SEVSNPPolicy): string | undefined {
  switch (true) {
    case p.minimumBuild === undefined:
      return "minimum_build is required";
    case p.minimumAPIVersion === "":
      return "minimum_api_version is required";
    case p.minimumABIVersion === "":
      return "minimum_abi_version is required";
    case p.minimumGuestSVN === undefined:
      return "minimum_guest_svn is required";
    case p.vmpl === undefined:
      return "vmpl is required";
    case p.vmpl! < 0 || p.vmpl! > 3:
      return "vmpl must be between 0 and 3";
    case p.hostData === "":
      return "host_data is required";
    case p.imageID === "":
      return "image_id is required";
    case p.familyID === "":
      return "family_id is required";
    case p.minimumLaunchMitigationVector === undefined:
      return "minimum_launch_mitigation_vector is required";
    case p.minimumCurrentMitigationVector === undefined:
      return "minimum_current_mitigation_vector is required";
    case p.requireAuthorKey || p.requireIDBlock:
      return "require_author_key and require_id_block are not supported (no trusted key material is modeled)";
  }
  let err = validateTCB(p.minimumTCB);
  if (err !== undefined) return `minimum_tcb: ${err}`;
  err = validateTCB(p.minimumLaunchTCB);
  if (err !== undefined) return `minimum_launch_tcb: ${err}`;
  err = validatePolicyVersion("minimum_api_version", p.minimumAPIVersion);
  if (err !== undefined) return err;
  err = validatePolicyVersion("minimum_abi_version", p.minimumABIVersion);
  if (err !== undefined) return err;
  for (const [name, f] of [
    ["host_data", { value: p.hostData, byteLen: 32 }],
    ["image_id", { value: p.imageID, byteLen: 16 }],
    ["family_id", { value: p.familyID, byteLen: 16 }],
  ] as [string, { value: string; byteLen: number }][]) {
    err = validatePolicyHex(name, f.value, f.byteLen);
    if (err !== undefined) return err;
  }
  return undefined;
}

function validatePolicyVersion(name: string, version: string): string | undefined {
  const dot = version.indexOf(".");
  if (dot < 0) return `${name} ${JSON.stringify(version)} is not maj.min`;
  const major = version.slice(0, dot);
  const minor = version.slice(dot + 1);
  if (!decimalDigits(major) || !decimalDigits(minor)) {
    return `${name} ${JSON.stringify(version)} is not maj.min`;
  }
  if (BigInt(major) > 255n) return `${name} major: value out of range`;
  if (BigInt(minor) > 255n) return `${name} minor: value out of range`;
  return undefined;
}

function decimalDigits(value: string): boolean {
  return value !== "" && /^[0-9]+$/.test(value);
}

function validateTCB(t: TCB): string | undefined {
  switch (true) {
    case t.blSpl === undefined:
      return "bl_spl is required";
    case t.teeSpl === undefined:
      return "tee_spl is required";
    case t.snpSpl === undefined:
      return "snp_spl is required";
    case t.ucodeSpl === undefined:
      return "ucode_spl is required";
  }
  return undefined;
}

// validateTDXPolicy rejects a block with any absent or malformed required
// member (Go: TDXPolicy.Validate).
export function validateTDXPolicy(p: TDXPolicy): string | undefined {
  switch (true) {
    case p.qeVendorID === "":
      return "qe_vendor_id is required";
    case p.minimumTEETCBSVN === "":
      return "minimum_tee_tcb_svn is required";
    case p.mrSeam === "":
      return "mr_seam is required";
    case p.tdAttributes === "":
      return "td_attributes is required";
    case p.xfam === "":
      return "xfam is required";
    case p.minimumTCBEvaluationDataNumber === undefined:
      return "minimum_tcb_evaluation_data_number is required";
    case p.minimumTCBEvaluationDataNumber! < 0:
      // A negative minimum would pass for any collateral, silently
      // disabling the freshness floor.
      return "minimum_tcb_evaluation_data_number must not be negative";
    case (p.platformMeasurements ?? []).length === 0:
      return "platform_measurements must not be empty";
  }
  for (const [name, f] of [
    ["qe_vendor_id", { value: p.qeVendorID, byteLen: 16 }],
    ["minimum_tee_tcb_svn", { value: p.minimumTEETCBSVN, byteLen: 16 }],
    ["mr_seam", { value: p.mrSeam, byteLen: 48 }],
    ["td_attributes", { value: p.tdAttributes, byteLen: 8 }],
    ["xfam", { value: p.xfam, byteLen: 8 }],
  ] as [string, { value: string; byteLen: number }][]) {
    const err = validatePolicyHex(name, f.value, f.byteLen);
    if (err !== undefined) return err;
  }
  return undefined;
}

function validatePolicyHex(name: string, value: string, byteLen: number): string | undefined {
  if (value !== value.toLowerCase()) {
    return `${name} must be lowercase hex`;
  }
  try {
    decodeHexPolicy(name, value, byteLen);
  } catch (err) {
    return err instanceof Error ? err.message : String(err);
  }
  return undefined;
}

// decodeHexPolicy decodes a required hex policy value of an exact byte
// length (Go: policy.DecodeHex). Throws a plain Error; the caller assigns
// the rejection layer.
export function decodeHexPolicy(name: string, value: string, wantLen: number): Uint8Array {
  let b: Uint8Array;
  try {
    b = decodeHex(value);
  } catch (err) {
    throw new Error(`${name} is not hex: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (b.length !== wantLen) {
    throw new Error(`${name} must be ${wantLen} bytes, got ${b.length}`);
  }
  return b;
}

function truncID(id: string): string {
  return id.length > 16 ? id.slice(0, 16) : id;
}

// policyFor looks up the appraisal policy for an authenticated platform
// identifier (lowercase hex) extracted from verified evidence, and asserts
// the policy's platform matches the evidence platform. An identifier absent
// from the machines map is an error: the machine is not endorsed.
export function policyFor(
  a: Artifact,
  identifierHex: string,
  platform: string,
): { name: string; policy: Policy } {
  const name = a.machines.get(identifierHex);
  if (name === undefined) {
    throw policyError(`platform identifier ${truncID(identifierHex)}... is not endorsed`);
  }
  const p = a.policies.get(name)!;
  if (p.platform !== platform) {
    throw policyError(
      `policy ${JSON.stringify(name)} is for platform ${JSON.stringify(p.platform)}, evidence is ${JSON.stringify(platform)}`,
    );
  }
  return { name, policy: p };
}

// resolvePlatformMeasurement selects the single measurements-map entry the
// policy allows whose MRTD/RTMR0 equal the quote's authenticated values,
// returning its name. Only entries measured for the required VM shape are
// candidates, so a quote from a machine-endorsed but wrong-shaped VM
// resolves nothing. The measurement inputs must come from a verified quote.
export function resolvePlatformMeasurement(
  a: Artifact,
  p: TDXPolicy,
  required: Shape | undefined,
  mrtdHex: string,
  rtmr0Hex: string,
): { name: string; measurement: PlatformMeasurement } {
  if (required === undefined) {
    throw policyError("required VM shape is missing");
  }
  let anyShapeMatch = false;
  for (const ref of p.platformMeasurements ?? []) {
    const m = a.measurements.get(ref);
    if (m === undefined || m.shape === undefined || !shapeSatisfies(m.shape, required)) {
      continue;
    }
    anyShapeMatch = true;
    if (m.mrtd === mrtdHex && m.rtmr0 === rtmr0Hex) {
      return { name: ref, measurement: m };
    }
  }
  if (!anyShapeMatch) {
    throw policyError(`no endorsed platform measurement matches the required VM shape ${JSON.stringify(required)}`);
  }
  throw policyError(`platform measurements (mrtd ${truncID(mrtdHex)}...) do not match any allowed configuration`);
}
