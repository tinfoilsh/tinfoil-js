export const POLICY_RESERVED_1_BIT = 17;
export const REPORT_SIZE = 0x4A0;
export const SIGNATURE_OFFSET = 0x2A0;
const ECDSA_RS_SIZE = 72;
export const ECDSA_P384_SHA384_SIGNATURE_SIZE = ECDSA_RS_SIZE + ECDSA_RS_SIZE;

export const ZEN3ZEN4_FAMILY = 0x19;
export const ZEN5_FAMILY = 0x1A;
export const MILAN_MODEL = 0 | 1;
export const GENOA_MODEL = (1 << 4) | 1;
export const TURIN_MODEL = 2;

export enum ReportSigner {
  VcekReportSigner = 0,
  VlekReportSigner = 1,
  endorseReserved2 = 2,
  endorseReserved3 = 3,
  endorseReserved4 = 4,
  endorseReserved5 = 5,
  endorseReserved6 = 6,
  NoneReportSigner = 7,
}
