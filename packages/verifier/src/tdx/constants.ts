// Quote structure sizes
export const TDX_HEADER_SIZE = 48;
export const TDX_BODY_SIZE = 584;
export const TDX_SIGNED_DATA_SIZE_OFFSET = TDX_HEADER_SIZE + TDX_BODY_SIZE; // 0x278
export const TDX_SIGNED_REGION_SIZE = TDX_SIGNED_DATA_SIZE_OFFSET; // 632 bytes
export const TDX_MIN_QUOTE_SIZE = 0x3FC; // 1020 bytes

// Header constraints
export const TDX_QUOTE_VERSION = 4;
export const TDX_ATTESTATION_KEY_TYPE = 2; // ECDSA-256-with-P-256
export const TDX_TEE_TYPE = 0x00000081;

export const INTEL_QE_VENDOR_ID = new Uint8Array([
  0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9,
  0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07,
]);

// Certification data
export const CERT_TYPE_QE_REPORT = 6;
export const PCK_CERT_CHAIN_TYPE = 5;
export const QE_REPORT_SIZE = 384;
export const ECDSA_P256_SIGNATURE_SIZE = 64;
export const ECDSA_P256_KEY_SIZE = 64;

// TD Quote Body offsets (relative to body start)
export const BODY_TEE_TCB_SVN_SIZE = 16;
export const BODY_MR_SEAM_SIZE = 48;
export const BODY_MR_SIGNER_SEAM_SIZE = 48;
export const BODY_SEAM_ATTRIBUTES_SIZE = 8;
export const BODY_TD_ATTRIBUTES_SIZE = 8;
export const BODY_XFAM_SIZE = 8;
export const BODY_MR_TD_SIZE = 48;
export const BODY_MR_CONFIG_ID_SIZE = 48;
export const BODY_MR_OWNER_SIZE = 48;
export const BODY_MR_OWNER_CONFIG_SIZE = 48;
export const BODY_REPORT_DATA_SIZE = 64;
export const RTMR_SIZE = 48;
export const RTMR_COUNT = 4;

// XFAM validation bitmasks
export const XFAM_FIXED1 = 0x00000003n;
export const XFAM_FIXED0 = 0x0006DBE7n;

// TD Attributes validation bitmasks
export const TD_ATTRIBUTES_DEBUG = 0x1n;
export const TD_ATTRIBUTES_SEPT_VE_DIS = 1n << 28n;
export const TD_ATTRIBUTES_PKS = 1n << 30n;
export const TD_ATTRIBUTES_PERFMON = 1n << 63n;
export const TD_ATTRIBUTES_ALLOWED =
  TD_ATTRIBUTES_DEBUG | TD_ATTRIBUTES_SEPT_VE_DIS | TD_ATTRIBUTES_PKS | TD_ATTRIBUTES_PERFMON;

// Default policy values
export const DEFAULT_TD_ATTRIBUTES = new Uint8Array([0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00]);
export const DEFAULT_XFAM = new Uint8Array([0xe7, 0x02, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00]);
export const DEFAULT_MINIMUM_TEE_TCB_SVN = new Uint8Array([
  0x03, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

// Accepted MR_SEAM values from Intel TDX Module releases
export const ACCEPTED_MR_SEAMS: Uint8Array[] = [
  // v2.0.08
  new Uint8Array([
    0x47, 0x6a, 0x29, 0x97, 0xc6, 0x2b, 0xcc, 0xc7, 0x83, 0x70, 0x91, 0x3d,
    0x0a, 0x80, 0xb9, 0x56, 0xe3, 0x72, 0x1b, 0x24, 0x27, 0x2b, 0xc6, 0x6c,
    0x4d, 0x63, 0x07, 0xce, 0xd4, 0xbe, 0x28, 0x65, 0xc4, 0x0e, 0x26, 0xaf,
    0xac, 0x75, 0xf1, 0x2d, 0xf3, 0x42, 0x5b, 0x03, 0xeb, 0x59, 0xea, 0x7c,
  ]),
  // v1.5.16
  new Uint8Array([
    0x7b, 0xf0, 0x63, 0x28, 0x0e, 0x94, 0xfb, 0x05, 0x1f, 0x5d, 0xd7, 0xb1,
    0xfc, 0x59, 0xce, 0x9a, 0xac, 0x42, 0xbb, 0x96, 0x1d, 0xf8, 0xd4, 0x4b,
    0x70, 0x9c, 0x9b, 0x0f, 0xf8, 0x7a, 0x7b, 0x4d, 0xf6, 0x48, 0x65, 0x7b,
    0xa6, 0xd1, 0x18, 0x95, 0x89, 0xfe, 0xab, 0x1d, 0x5a, 0x3c, 0x9a, 0x9d,
  ]),
  // v2.0.02
  new Uint8Array([
    0x68, 0x5f, 0x89, 0x1e, 0xa5, 0xc2, 0x0e, 0x8f, 0xa2, 0x7b, 0x15, 0x1b,
    0xf3, 0x4b, 0xf3, 0xb5, 0x0f, 0xba, 0xf7, 0x14, 0x3c, 0xc5, 0x36, 0x62,
    0x72, 0x7c, 0xbd, 0xb1, 0x67, 0xc0, 0xad, 0x83, 0x85, 0xf1, 0xf6, 0xf3,
    0x57, 0x15, 0x39, 0xa9, 0x1e, 0x10, 0x4a, 0x1c, 0x96, 0xd7, 0x5e, 0x04,
  ]),
  // v1.5.08
  new Uint8Array([
    0x49, 0xb6, 0x6f, 0xaa, 0x45, 0x1d, 0x19, 0xeb, 0xbd, 0xbe, 0x89, 0x37,
    0x1b, 0x8d, 0xaf, 0x2b, 0x65, 0xaa, 0x39, 0x84, 0xec, 0x90, 0x11, 0x03,
    0x43, 0xe9, 0xe2, 0xee, 0xc1, 0x16, 0xaf, 0x08, 0x85, 0x0f, 0xa2, 0x0e,
    0x3b, 0x1a, 0xa9, 0xa8, 0x74, 0xd7, 0x7a, 0x65, 0x38, 0x0e, 0xe7, 0xe6,
  ]),
];

export const ZERO_48 = new Uint8Array(48);

export const RTMR3_ZERO =
  '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';

// Intel PCS (Provisioning Certification Service) configuration
export const INTEL_PCS_BASE_URL = 'https://api.trustedservices.intel.com';
export const TDX_PROXY_HOST = 'tdx-proxy.tinfoil.sh';
export const MINIMUM_TCB_EVALUATION_DATA_NUMBER = 19;

// Intel PCS API v4 paths (TDX-specific endpoints)
export const PCS_TCB_INFO_PATH = '/tdx/certification/v4/tcb';
export const PCS_QE_IDENTITY_PATH = '/tdx/certification/v4/qe/identity';
export const PCS_PCK_CRL_PATH = '/sgx/certification/v4/pckcrl';
export const PCS_ROOT_CA_CRL_URL = 'https://certificates.trustedservices.intel.com/IntelSGXRootCA.der';

// Intel SGX PCK Certificate Extension OIDs
export const SGX_EXTENSIONS_OID = '1.2.840.113741.1.13.1';
export const SGX_FMSPC_OID = '1.2.840.113741.1.13.1.4';
export const SGX_PCEID_OID = '1.2.840.113741.1.13.1.3';
export const SGX_TCB_OID = '1.2.840.113741.1.13.1.2';
export const SGX_PCESVN_OID = '1.2.840.113741.1.13.1.2.17';
export const SGX_CPUSVN_OID = '1.2.840.113741.1.13.1.2.18';
export const SGX_TYPE_OID = '1.2.840.113741.1.13.1.5';

// Acceptable TCB statuses (others like Revoked, OutOfDate are rejected)
export const ACCEPTABLE_TCB_STATUSES = new Set([
  'UpToDate',
  'SWHardeningNeeded',
  'ConfigurationNeeded',
  'ConfigurationAndSWHardeningNeeded',
]);

export const INTEL_SGX_ROOT_CA_PEM = `-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----`;
