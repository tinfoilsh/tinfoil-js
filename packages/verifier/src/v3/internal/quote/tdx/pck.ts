/**
 * The PCK certificate chain a quote carries and the SGX extension of its
 * leaf: the platform identity (PPID), the TCB the certificate was issued
 * for (sixteen CPU SVN components, the PCE SVN, the raw CPU SVN), the PCE
 * id and the FMSPC that selects the platform's TCB info.
 */
import { expectSequence, extension, isUniversal, type Certificate, X509Error } from "../../x509/certificate.js";
import { decode, DerError, integer, oid, TAG, type DerElement } from "../../x509/der.js";

export const OID_SGX_EXTENSION = "1.2.840.113741.1.13.1";
const OID_PPID = "1.2.840.113741.1.13.1.1";
const OID_TCB = "1.2.840.113741.1.13.1.2";
const OID_TCB_PREFIX = "1.2.840.113741.1.13.1.2.";
const OID_PCE_SVN = "1.2.840.113741.1.13.1.2.17";
const OID_CPU_SVN = "1.2.840.113741.1.13.1.2.18";
const OID_PCE_ID = "1.2.840.113741.1.13.1.3";
const OID_FMSPC = "1.2.840.113741.1.13.1.4";

/** Every PCK certificate carries exactly these: authority and subject key ids, CRL distribution points, key usage, basic constraints, and the SGX extension. */
const PCK_EXTENSION_COUNT = 6;
const TCB_COMPONENT_COUNT = 16;
const TCB_ENTRY_COUNT = 18;
export const PPID_SIZE = 16;
export const CPU_SVN_SIZE = 16;
export const PCE_ID_SIZE = 2;
export const FMSPC_SIZE = 6;

export interface PckExtensions {
  readonly ppid: Uint8Array;
  /** The sixteen TCB components the certificate was issued for, by position. */
  readonly cpuSvnComponents: Uint8Array;
  readonly cpuSvn: Uint8Array;
  readonly pceSvn: number;
  readonly pceId: Uint8Array;
  readonly fmspc: Uint8Array;
}

/** Reads the SGX extension of a PCK leaf certificate; every field is required. */
export function pckExtensions(leaf: Certificate): PckExtensions {
  if (leaf.extensions.length !== PCK_EXTENSION_COUNT) {
    throw new Error(`PCK certificate carries ${leaf.extensions.length} extensions, expected ${PCK_EXTENSION_COUNT}`);
  }
  const ext = extension(leaf, OID_SGX_EXTENSION);
  if (ext === undefined) throw new Error("PCK certificate has no SGX extension");
  try {
    return parseSgxExtension(decode(ext.value));
  } catch (err) {
    if (err instanceof DerError || err instanceof X509Error) throw new Error(`PCK certificate SGX extension: ${err.message}`);
    throw err;
  }
}

function parseSgxExtension(root: DerElement): PckExtensions {
  let ppid: Uint8Array | undefined;
  let pceId: Uint8Array | undefined;
  let fmspc: Uint8Array | undefined;
  let tcb: Omit<PckExtensions, "ppid" | "pceId" | "fmspc"> | undefined;
  const seen = new Set<string>();
  for (const entry of expectSequence(root, "SGX extension")) {
    const [id, value] = pair(entry, "SGX extension entry");
    if (seen.has(id)) throw new Error(`repeated SGX extension entry ${id}`);
    seen.add(id);
    switch (id) {
      case OID_PPID:
        ppid = octets(value, "PPID", PPID_SIZE);
        break;
      case OID_PCE_ID:
        pceId = octets(value, "PCEID", PCE_ID_SIZE);
        break;
      case OID_FMSPC:
        fmspc = octets(value, "FMSPC", FMSPC_SIZE);
        break;
      case OID_TCB:
        tcb = parseTcb(value);
        break;
      default:
        break; // Entries this verifier does not read are allowed.
    }
  }
  if (ppid === undefined) throw new Error("SGX extension has no PPID");
  if (pceId === undefined) throw new Error("SGX extension has no PCEID");
  if (fmspc === undefined) throw new Error("SGX extension has no FMSPC");
  if (tcb === undefined) throw new Error("SGX extension has no TCB");
  return { ppid, pceId, fmspc, ...tcb };
}

function parseTcb(value: DerElement): Omit<PckExtensions, "ppid" | "pceId" | "fmspc"> {
  const entries = expectSequence(value, "SGX TCB extension");
  if (entries.length !== TCB_ENTRY_COUNT) throw new Error(`SGX TCB extension holds ${entries.length} entries, expected ${TCB_ENTRY_COUNT}`);
  const components = new Uint8Array(TCB_COMPONENT_COUNT);
  const seen = new Set<string>();
  let pceSvn: number | undefined;
  let cpuSvn: Uint8Array | undefined;
  for (const entry of entries) {
    const [id, v] = pair(entry, "SGX TCB entry");
    if (seen.has(id)) throw new Error(`repeated SGX TCB entry ${id}`);
    seen.add(id);
    if (id === OID_PCE_SVN) {
      pceSvn = smallInteger(v, "PCESVN", 0xffff);
    } else if (id === OID_CPU_SVN) {
      cpuSvn = octets(v, "CPUSVN", CPU_SVN_SIZE);
    } else if (id.startsWith(OID_TCB_PREFIX)) {
      const n = Number(id.slice(OID_TCB_PREFIX.length));
      if (!Number.isInteger(n) || n < 1 || n > TCB_COMPONENT_COUNT) throw new Error(`unexpected SGX TCB entry ${id}`);
      components[n - 1] = smallInteger(v, `TCB component ${n}`, 0xff);
    } else {
      throw new Error(`unexpected SGX TCB entry ${id}`);
    }
  }
  if (seen.size !== TCB_ENTRY_COUNT || pceSvn === undefined || cpuSvn === undefined) {
    throw new Error("SGX TCB extension is missing a component, the PCESVN or the CPUSVN");
  }
  return { cpuSvnComponents: components, cpuSvn, pceSvn };
}

function pair(entry: DerElement, what: string): [string, DerElement] {
  const parts = expectSequence(entry, what);
  if (parts.length !== 2) throw new Error(`${what} must hold an OID and a value`);
  return [oid(parts[0]), parts[1]];
}

function octets(e: DerElement, what: string, size: number): Uint8Array {
  if (!isUniversal(e, TAG.OCTET_STRING)) throw new Error(`${what} must be an OCTET STRING`);
  if (e.value.length !== size) throw new Error(`${what} is ${e.value.length} bytes, expected ${size}`);
  return e.value.slice();
}

function smallInteger(e: DerElement, what: string, max: number): number {
  const n = integer(e);
  if (n < 0n || n > BigInt(max)) throw new Error(`${what} ${n} is outside 0..${max}`);
  return Number(n);
}
