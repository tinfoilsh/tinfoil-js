import { parseJSON } from '../encoding.js';
import { requireThat } from '../quote/crypto.js';
import type { TCB } from '../sev/report.js';

export const PLATFORM_V1 = 'https://tinfoil.sh/predicate/platform-endorsements/v1';
export const PLATFORM_V2 = 'https://tinfoil.sh/predicate/platform-endorsements/v2';
export interface Shape { cpus: number; memory_mb: number; gpus?: number; disks: number }
export interface PlatformMeasurement { mrtd: string; rtmr0: string; shape: Shape; stack?: { qemu?: string; ovmf?: string } }
export const GUEST_BITS = { smt: 16, migrate_ma: 18, debug: 19, single_socket: 20, cxl_allowed: 21, mem_aes256_xts: 22, rapl_dis: 23, ciphertext_hiding_dram: 24, page_swap_disable: 25 } as const;
export const PLATFORM_BITS = { smt_enabled: 0, tsme_enabled: 1, ecc_enabled: 2, rapl_disabled: 3, ciphertext_hiding_dram: 4, alias_check_complete: 5, iommu_write_safe: 6, tio_enabled: 7 } as const;
export interface SNPPolicy {
  minimum_build: number; minimum_api_version: string; minimum_abi_version: string; minimum_guest_svn: number;
  minimum_tcb: TCB; minimum_launch_tcb: TCB; guest_policy: Record<keyof typeof GUEST_BITS, boolean>; platform_info: Record<keyof typeof PLATFORM_BITS, boolean>;
  permit_provisional_firmware: boolean; vmpl: number; host_data?: string; image_id: string; family_id: string;
  require_author_key?: boolean; require_id_block?: boolean; minimum_launch_mitigation_vector: bigint; minimum_current_mitigation_vector: bigint;
}
export interface TDXPolicy {
  qe_vendor_id: string; minimum_tee_tcb_svn: string; mr_seam: string; td_attributes: string; xfam: string;
  minimum_tcb_evaluation_data_number: number; platform_measurements?: string[];
}
export type Policy = { platform: 'sev-snp'; sev_snp: SNPPolicy } | { platform: 'tdx'; tdx: TDXPolicy };
export interface PlatformArtifact { format: string; measurements: Record<string, PlatformMeasurement>; machines: Record<string, string>; policies: Record<string, Policy> }
function object(value: unknown): Record<string, any> {
  requireThat(value !== null && typeof value === 'object' && !Array.isArray(value), 'policy value must be an object'); return value as Record<string, any>;
}
function fields(value: unknown, allowed: string[], required = allowed): Record<string, any> {
  const o = object(value);
  requireThat(Object.keys(o).every(k => allowed.includes(k)), 'unknown policy member');
  requireThat(required.every(k => Object.prototype.hasOwnProperty.call(o, k) && o[k] !== null && o[k] !== undefined), 'missing required policy member'); return o;
}
function uint(value: unknown, max: number, name: string): number {
  requireThat(Number.isSafeInteger(value) && (value as number) >= 0 && (value as number) <= max, `invalid ${name}`); return value as number;
}
function uint64(value: unknown, name: string): bigint {
  requireThat(typeof value === 'bigint' || typeof value === 'number' && Number.isSafeInteger(value), `invalid exact ${name}`);
  const n = BigInt(value); requireThat(n >= 0n && n <= 0xffffffffffffffffn, `invalid ${name}`); return n;
}
function hex(value: unknown, size: number, name: string): string {
  requireThat(typeof value === 'string' && value.length === size * 2 && /^[0-9a-f]+$/.test(value), `invalid ${name}`); return value;
}
export function version(value: string): number {
  requireThat(typeof value === 'string' && /^[0-9]+\.[0-9]+$/.test(value), 'invalid policy version');
  const [major, minor] = value.split('.').map(Number); return uint(major, 255, 'version major') * 256 + uint(minor, 255, 'version minor');
}
function flags<T extends Record<string, number>>(value: unknown, bits: T): Record<keyof T, boolean> {
  const o = fields(value ?? {}, Object.keys(bits), []), out = {} as Record<keyof T, boolean>;
  for (const name of Object.keys(bits)) { requireThat(o[name] === undefined || typeof o[name] === 'boolean', 'policy flag must be boolean'); out[name as keyof T] = o[name] ?? false; }
  return out;
}
function tcb(value: unknown): TCB {
  const o = fields(value, ['bl_spl', 'tee_spl', 'snp_spl', 'ucode_spl', 'fmc_spl'], ['bl_spl', 'tee_spl', 'snp_spl', 'ucode_spl']);
  const out: Record<string, number> = {}; for (const name of Object.keys(o)) out[name] = uint(o[name], 255, name); return out as TCB;
}
function snp(value: unknown, legacy: boolean): SNPPolicy {
  const required = ['minimum_build', 'minimum_api_version', 'minimum_abi_version', 'minimum_guest_svn', 'minimum_tcb', 'minimum_launch_tcb', 'vmpl', 'image_id', 'family_id', 'minimum_launch_mitigation_vector', 'minimum_current_mitigation_vector'];
  const o = fields(value, [...required, 'guest_policy', 'platform_info', 'permit_provisional_firmware', 'host_data', 'require_author_key', 'require_id_block'], required);
  requireThat(legacy ? typeof o.host_data === 'string' && o.host_data.length > 0 : o.host_data === undefined || o.host_data === '', 'host_data is required in platform v1 and excluded in v2');
  for (const name of ['permit_provisional_firmware', 'require_author_key', 'require_id_block']) requireThat(o[name] === undefined || typeof o[name] === 'boolean', `invalid ${name}`);
  requireThat(!o.require_author_key && !o.require_id_block, 'ID block launches are unsupported');
  version(o.minimum_api_version); version(o.minimum_abi_version);
  return {
    minimum_build: uint(o.minimum_build, 255, 'minimum_build'), minimum_api_version: o.minimum_api_version, minimum_abi_version: o.minimum_abi_version,
    minimum_guest_svn: uint(o.minimum_guest_svn, 0xffffffff, 'minimum_guest_svn'), minimum_tcb: tcb(o.minimum_tcb), minimum_launch_tcb: tcb(o.minimum_launch_tcb),
    guest_policy: flags(o.guest_policy, GUEST_BITS), platform_info: flags(o.platform_info, PLATFORM_BITS), permit_provisional_firmware: o.permit_provisional_firmware ?? false,
    vmpl: uint(o.vmpl, 3, 'vmpl'), ...(legacy ? { host_data: hex(o.host_data, 32, 'host_data') } : {}), image_id: hex(o.image_id, 16, 'image_id'), family_id: hex(o.family_id, 16, 'family_id'),
    minimum_launch_mitigation_vector: uint64(o.minimum_launch_mitigation_vector, 'minimum_launch_mitigation_vector'), minimum_current_mitigation_vector: uint64(o.minimum_current_mitigation_vector, 'minimum_current_mitigation_vector'),
  };
}
function tdx(value: unknown, legacy: boolean): TDXPolicy {
  const required = ['qe_vendor_id', 'minimum_tee_tcb_svn', 'mr_seam', 'td_attributes', 'xfam', 'minimum_tcb_evaluation_data_number'];
  const o = fields(value, [...required, 'platform_measurements'], required);
  const refs = o.platform_measurements ?? [];
  requireThat(Array.isArray(refs) && refs.every((v: unknown) => typeof v === 'string') && (legacy ? refs.length > 0 : refs.length === 0), 'invalid platform_measurements for platform profile');
  return { qe_vendor_id: hex(o.qe_vendor_id, 16, 'qe_vendor_id'), minimum_tee_tcb_svn: hex(o.minimum_tee_tcb_svn, 16, 'minimum_tee_tcb_svn'), mr_seam: hex(o.mr_seam, 48, 'mr_seam'), td_attributes: hex(o.td_attributes, 8, 'td_attributes'), xfam: hex(o.xfam, 8, 'xfam'), minimum_tcb_evaluation_data_number: uint(o.minimum_tcb_evaluation_data_number, Number.MAX_SAFE_INTEGER, 'minimum_tcb_evaluation_data_number'), ...(legacy ? { platform_measurements: refs.slice() } : {}) };
}
export function parsePlatformArtifact(value: unknown, expectedFormat?: string): PlatformArtifact {
  if (value instanceof Uint8Array || typeof value === 'string') value = parseJSON(value);
  const o = fields(value, ['format', 'measurements', 'machines', 'policies'], ['format', 'machines', 'policies']);
  requireThat([PLATFORM_V1, PLATFORM_V2].includes(o.format) && (!expectedFormat || o.format === expectedFormat), 'unsupported platform artifact format');
  const legacy = o.format === PLATFORM_V1;
  const policies: Record<string, Policy> = Object.create(null), measurements: Record<string, PlatformMeasurement> = Object.create(null), machines: Record<string, string> = Object.create(null);
  for (const [name, v] of Object.entries(object(o.policies))) {
    const p = fields(v, ['platform', 'sev_snp', 'tdx'], ['platform']);
    requireThat(p.platform === 'sev-snp' ? p.sev_snp !== undefined && p.tdx === undefined : p.platform === 'tdx' && p.tdx !== undefined && p.sev_snp === undefined, 'policy requires exactly its platform block');
    policies[name] = p.platform === 'sev-snp' ? { platform: 'sev-snp', sev_snp: snp(p.sev_snp, legacy) } : { platform: 'tdx', tdx: tdx(p.tdx, legacy) };
  }
  for (const [name, value] of Object.entries(object(o.measurements ?? {}))) {
    requireThat(legacy, 'platform v2 excludes workload measurements');
    const m = fields(value, ['mrtd', 'rtmr0', 'shape', 'stack'], ['mrtd', 'rtmr0', 'shape']);
    const s = fields(m.shape, ['cpus', 'memory_mb', 'gpus', 'disks'], ['cpus', 'memory_mb', 'disks']);
    const shape = { cpus: uint(s.cpus, Number.MAX_SAFE_INTEGER, 'cpus'), memory_mb: uint(s.memory_mb, Number.MAX_SAFE_INTEGER, 'memory_mb'), disks: uint(s.disks, Number.MAX_SAFE_INTEGER, 'disks'), ...(s.gpus === undefined ? {} : { gpus: uint(s.gpus, Number.MAX_SAFE_INTEGER, 'gpus') }) };
    requireThat(shape.cpus > 0 && shape.memory_mb > 0 && shape.disks > 0, 'platform shape dimensions must be positive');
    if (m.stack !== undefined) { const stack = fields(m.stack, ['qemu', 'ovmf'], []); requireThat(Object.values(stack).every(v => typeof v === 'string'), 'invalid platform stack'); }
    measurements[name] = { mrtd: hex(m.mrtd, 48, 'mrtd'), rtmr0: hex(m.rtmr0, 48, 'rtmr0'), shape, ...(m.stack === undefined ? {} : { stack: { ...m.stack } }) };
  }
  for (const p of Object.values(policies)) if (p.platform === 'tdx') for (const name of p.tdx.platform_measurements ?? []) requireThat(Object.prototype.hasOwnProperty.call(measurements, name), 'dangling platform measurement reference');
  for (const [id, name] of Object.entries(object(o.machines))) {
    requireThat(typeof name === 'string' && Object.prototype.hasOwnProperty.call(policies, name), 'machine refers to an unknown policy');
    hex(id, policies[name].platform === 'sev-snp' ? 64 : 16, 'machine identity'); machines[id] = name;
  }
  return { format: o.format, measurements, machines, policies };
}
export function shapeMatches(got: Shape, expected: Shape): boolean {
  return got.cpus === expected.cpus && got.memory_mb === expected.memory_mb && got.disks === expected.disks && (got.gpus === undefined || expected.gpus === undefined || got.gpus === expected.gpus);
}
