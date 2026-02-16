import type { TCBParts, SnpPlatformInfo, SnpPolicy } from './types.js';

export function tcbFromInt(tcb: bigint): TCBParts {
  return {
    ucodeSpl: Number((tcb >> 56n) & 0xffn),
    snpSpl: Number((tcb >> 48n) & 0xffn),
    teeSpl: Number((tcb >> 8n) & 0xffn),
    blSpl: Number(tcb & 0xffn),
  };
}

export function tcbMeetsMinimum(tcb: TCBParts, minimum: TCBParts): boolean {
  return (
    tcb.blSpl >= minimum.blSpl &&
    tcb.teeSpl >= minimum.teeSpl &&
    tcb.snpSpl >= minimum.snpSpl &&
    tcb.ucodeSpl >= minimum.ucodeSpl
  );
}

export function platformInfoFromInt(value: bigint): SnpPlatformInfo {
  return {
    smtEnabled: !!(value & 1n),
    tsmeEnabled: !!(value & 2n),
    eccEnabled: !!(value & 4n),
    raplDisabled: !!(value & 8n),
    ciphertextHidingDramEnabled: !!(value & 16n),
    aliasCheckComplete: !!(value & 32n),
    tioEnabled: !!(value & 128n),
  };
}

export function policyFromInt(value: bigint): SnpPolicy {
  return {
    abiMinor: Number(value & 0xffn),
    abiMajor: Number((value >> 8n) & 0xffn),
    smt: !!(value & (1n << 16n)),
    migrateMa: !!(value & (1n << 18n)),
    debug: !!(value & (1n << 19n)),
    singleSocket: !!(value & (1n << 20n)),
    cxlAllowed: !!(value & (1n << 21n)),
    memAes256Xts: !!(value & (1n << 22n)),
    raplDis: !!(value & (1n << 23n)),
    ciphertextHidingDram: !!(value & (1n << 24n)),
    pageSwapDisabled: !!(value & (1n << 25n)),
  };
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Hex string must have even length');
  }
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error('Hex string contains invalid characters');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}
