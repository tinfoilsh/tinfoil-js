import { GUEST_BITS, PLATFORM_BITS, version, type SNPPolicy } from '../policy/index.js';
import { equal, requireThat, unhex, zero } from '../quote/crypto.js';
import { decodeTCB, Report, tcbAtLeast } from './report.js';

export function validateSEV(report: Report, policy: SNPPolicy, launch: string, reportData: Uint8Array, hostData: string): void {
  const hasFMC = policy.minimum_tcb.fmc_spl !== undefined && policy.minimum_launch_tcb.fmc_spl !== undefined;
  if (report.product === 'Turin') requireThat(hasFMC && policy.platform_info.iommu_write_safe, 'Turin policy requires FMC floors and IOMMU write safety');
  else requireThat(policy.minimum_tcb.fmc_spl === undefined && policy.minimum_launch_tcb.fmc_spl === undefined && !policy.platform_info.iommu_write_safe, 'Genoa policy cannot use Turin-only fields');
  requireThat(report.u32(4) >= policy.minimum_guest_svn, 'guest SVN below policy floor');
  requireThat(report.u32(0x30) === policy.vmpl, 'VMPL mismatch');
  requireThat(Number(report.policy & 0xffffn) >= version(policy.minimum_abi_version), 'guest ABI below policy floor');
  for (const [name, bit] of Object.entries(GUEST_BITS)) requireThat(Boolean(report.policy & (1n << BigInt(bit))) === policy.guest_policy[name as keyof typeof GUEST_BITS], `guest policy ${name} mismatch`);
  for (const [name, bit] of Object.entries(PLATFORM_BITS)) requireThat(Boolean(report.platformInfo & (1n << BigInt(bit))) === policy.platform_info[name as keyof typeof PLATFORM_BITS], `platform info ${name} mismatch`);
  const current = decodeTCB(report.u64(0x38), report.product), committed = decodeTCB(report.u64(0x1e0), report.product), reported = report.reportedTCB;
  requireThat(tcbAtLeast(reported, policy.minimum_tcb) && tcbAtLeast(current, reported), 'report TCB is below policy floor or exceeds current TCB');
  requireThat(tcbAtLeast(decodeTCB(report.u64(0x1f0), report.product), policy.minimum_launch_tcb), 'launch TCB below policy floor');
  requireThat(tcbAtLeast(current, committed) && (policy.permit_provisional_firmware || tcbAtLeast(committed, current)), 'committed and current TCB violate provisional firmware policy');
  const b = report.bytes, currentVersion = b[0x1ea] * 256 + b[0x1e9], committedVersion = b[0x1ee] * 256 + b[0x1ed];
  requireThat(b[0x1e8] >= policy.minimum_build && currentVersion >= version(policy.minimum_api_version), 'firmware build or API version below floor');
  requireThat(b[0x1ec] <= b[0x1e8] && committedVersion <= currentVersion && (policy.permit_provisional_firmware || b[0x1ec] === b[0x1e8] && committedVersion === currentVersion), 'committed and current firmware versions violate policy');
  requireThat(report.version >= 5 || (policy.minimum_launch_mitigation_vector === 0n && policy.minimum_current_mitigation_vector === 0n), 'nonzero mitigation floors require SNP report version 5');
  for (const [offset, expected] of [[0x1f8, policy.minimum_launch_mitigation_vector], [0x200, policy.minimum_current_mitigation_vector]] as const) requireThat((report.u64(offset) & expected) === expected, 'report mitigation vector lacks required bits');
  for (const [offset, size, expected, name] of [[0x90, 48, launch, 'launch'], [0xc0, 32, hostData, 'HOST_DATA'], [0x10, 16, policy.family_id, 'family ID'], [0x20, 16, policy.image_id, 'image ID']] as const) requireThat(equal(report.field(offset, size), unhex(expected, size)), `SEV ${name} mismatch`);
  requireThat(equal(report.field(0x50, 64), reportData), 'SEV REPORT_DATA mismatch');
  requireThat((report.signerInfo & 1) === 0 && zero(report.field(0xe0, 48)) && zero(report.field(0x110, 48)), 'ID block and author-key launches are unsupported');
}
