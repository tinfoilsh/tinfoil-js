import type { TDXPolicy } from '../policy/index.js';
import type { TDXMeasurement } from '../types.js';
import { equal, requireThat, unhex, zero } from '../quote/crypto.js';
import type { AuthenticatedTDX } from './authenticate.js';

export function validateTDX(authenticated: AuthenticatedTDX, policy: TDXPolicy, measurement: TDXMeasurement, reportData: Uint8Array, configID: Uint8Array): void {
  const { quote, tcbEvaluationDataNumber } = authenticated;
  requireThat(equal(quote.bytes.slice(12, 28), unhex(policy.qe_vendor_id, 16)), 'QE vendor does not match policy');
  const min = unhex(policy.minimum_tee_tcb_svn, 16);
  requireThat(quote.teeTCBSVN.every((b, i) => b >= min[i]), 'TEE TCB SVN below policy floor');
  requireThat(tcbEvaluationDataNumber >= policy.minimum_tcb_evaluation_data_number, 'Intel TCB evaluation number below policy floor');
  for (const [offset, size, expected, label] of [[0x10, 48, policy.mr_seam, 'MRSEAM'], [0x78, 8, policy.td_attributes, 'TD_ATTRIBUTES'], [0x80, 8, policy.xfam, 'XFAM'], [0x88, 48, measurement.mrtd, 'MRTD'], [0x148, 48, measurement.rtmr0, 'RTMR0'], [0x178, 48, measurement.rtmr1, 'RTMR1'], [0x1a8, 48, measurement.rtmr2, 'RTMR2'], [0x1d8, 48, measurement.rtmr3, 'RTMR3']] as const) requireThat(equal(quote.field(offset, size), unhex(expected, size)), `TDX ${label} mismatch`);
  requireThat(equal(quote.field(0xb8, 48), configID) && zero(quote.field(0xe8, 48)) && zero(quote.field(0x118, 48)), 'TDX config/owner measurement mismatch');
  requireThat(equal(quote.field(0x208, 64), reportData), 'TDX REPORT_DATA mismatch');
  const attr = new DataView(quote.field(0x78, 8).buffer).getBigUint64(0, true), xfam = new DataView(quote.field(0x80, 8).buffer).getBigUint64(0, true);
  requireThat((attr & 1n) === 0n && (attr & ~((1n << 28n) | (1n << 30n) | (1n << 63n))) === 0n, 'debug or reserved TDX attribute is set');
  requireThat((xfam & 3n) === 3n && (xfam & ~0x6dbe7n) === 0n, 'TDX XFAM contains unsupported features');
}
