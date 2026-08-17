// Intel PCS values and parsers, a 1:1 port of go-tdx-guest/pcs plus the
// lenient JSON decoding go-tdx-guest performs on PCS response bodies with
// encoding/json (case-exact keys as emitted by Intel, unknown members
// ignored, typed members validated). All errors are plain Errors.

import { decodeHex, encodeHex, utf8DecodeLenient, utf8Encode } from "../bytes.js";
import { children, content, decodeOID, decodeUint, readTLV, type Certificate, type TLV } from "./der.js";

const ppidSize = 16;
const cpuSvnSize = 16;
const pceIDSize = 2;
const fmspcSize = 6;
const tcbComponentSize = 16;
const tcbExtensionSize = 18;
const pckCertExtensionSize = 6;
const sgxExtensionMinSize = 4;

const pcsSgxBaseURL = "https://api.trustedservices.intel.com/sgx/certification/v4";
const pcsTdxBaseURL = "https://api.trustedservices.intel.com/tdx/certification/v4";

export const OidSgxExtension = "1.2.840.113741.1.13.1";
const OidPPID = "1.2.840.113741.1.13.1.1";
const OidTCB = "1.2.840.113741.1.13.1.2";
const OidPCEID = "1.2.840.113741.1.13.1.3";
const OidFMSPC = "1.2.840.113741.1.13.1.4";
const OidPCESvn = "1.2.840.113741.1.13.1.2.17";
const OidCPUSvn = "1.2.840.113741.1.13.1.2.18";

export function pckCrlURL(ca: string): string {
  return `${pcsSgxBaseURL}/pckcrl?ca=${ca}&encoding=der`;
}

export function tcbInfoURL(fmspc: string): string {
  return `${pcsTdxBaseURL}/tcb?fmspc=${fmspc}`;
}

export function qeIdentityURL(): string {
  return `${pcsTdxBaseURL}/qe/identity`;
}

// PCK certificate SGX extension (pcs.PckCertificateExtensions).

export interface PckCertTCB {
  pceSvn: number;
  cpuSvn: Uint8Array;
  cpuSvnComponents: Uint8Array;
}

export interface PckExtensions {
  ppid: string;
  tcb: PckCertTCB;
  pceid: string;
  fmspc: string;
}

const tagInteger = 0x02;
const tagOctetString = 0x04;
const tagOID = 0x06;
const tagSequence = 0x10;

function entryOIDAndValue(b: Uint8Array, entry: TLV, what: string): { oid: string; value: TLV } {
  if (entry.cls !== 0 || entry.tag !== tagSequence) {
    throw new Error(`could not parse ${what} in the PCK certificate`);
  }
  const parts = children(b, entry);
  if (parts.length !== 2 || parts[0].cls !== 0 || parts[0].tag !== tagOID) {
    throw new Error(`could not parse ${what} in the PCK certificate`);
  }
  return { oid: decodeOID(content(b, parts[0])), value: parts[1] };
}

function octetStringValue(b: Uint8Array, v: TLV, field: string, size: number): string {
  if (v.cls !== 0 || v.tag !== tagOctetString) {
    throw new Error(`could not parse ${field} extension as an octet string`);
  }
  const val = content(b, v);
  if (val.length !== size) {
    throw new Error(`${field} extension's value size is ${val.length}, expected ${size}`);
  }
  return encodeHex(val);
}

function extractTcbExtension(b: Uint8Array, value: TLV): PckCertTCB {
  if (value.cls !== 0 || value.tag !== tagSequence) {
    throw new Error("could not parse TCB extension present inside the SGX extension in PCK certificate");
  }
  const tcbExtension = children(b, value);
  if (tcbExtension.length !== tcbExtensionSize) {
    throw new Error(`TCB extension is of size ${tcbExtension.length}, expected ${tcbExtensionSize}`);
  }
  const tcb: PckCertTCB = {
    pceSvn: 0,
    cpuSvn: new Uint8Array(0),
    cpuSvnComponents: new Uint8Array(tcbComponentSize),
  };
  for (const ext of tcbExtension) {
    const { oid, value: v } = entryOIDAndValue(b, ext, "TCB component inside the TCB extension");
    for (let i = 0; i < tcbComponentSize; i++) {
      if (oid === `${OidTCB}.${i + 1}`) {
        if (v.tag !== tagInteger || v.cls !== 0) {
          throw new Error(`sgxTcbComponent${i + 1} extension is not an INTEGER`);
        }
        const val = decodeUint(content(b, v), `sgxTcbComponent${i + 1}`);
        if (val > 255) throw new Error(`int value for field sgxTcbComponent${i + 1} isn't a byte: ${val}`);
        tcb.cpuSvnComponents[i] = val;
        break;
      }
    }
    if (oid === OidPCESvn) {
      if (v.tag !== tagInteger || v.cls !== 0) throw new Error("PCESvn extension is not an INTEGER");
      const val = decodeUint(content(b, v), "PCESvn");
      if (val > 65535) throw new Error(`int value for field PCESvn isn't a uint16: ${val}`);
      tcb.pceSvn = val;
    }
    if (oid === OidCPUSvn) {
      if (v.tag !== tagOctetString || v.cls !== 0) {
        throw new Error("CPUSVN component in TCB extension is not an octet string");
      }
      const val = content(b, v);
      if (val.length !== cpuSvnSize) {
        throw new Error(`CPUSVN component in TCB extension is of size ${val.length}, expected ${cpuSvnSize}`);
      }
      tcb.cpuSvn = val;
    }
  }
  return tcb;
}

// pckCertificateExtensions extracts the SGX x509v3 extension fields required
// for verification, enforcing the exact extension count the library pins.
export function pckCertificateExtensions(cert: Certificate): PckExtensions {
  if (cert.extensions.length !== pckCertExtensionSize) {
    throw new Error(`PCK certificate extensions length found ${cert.extensions.length}. Expected ${pckCertExtensionSize}`);
  }
  const sgxExt = cert.extensions.find((e) => e.oid === OidSgxExtension);
  if (sgxExt === undefined) {
    throw new Error("could not find SGX extension present in the PCK certificate");
  }
  const outer = readTLV(sgxExt.value, 0);
  if (outer.cls !== 0 || outer.tag !== tagSequence || outer.end !== sgxExt.value.length) {
    throw new Error("could not parse SGX extension present in the PCK certificate");
  }
  const entries = children(sgxExt.value, outer);
  if (entries.length < sgxExtensionMinSize) {
    throw new Error(`SGX Extension has length ${entries.length}. It should have a minimum length of ${sgxExtensionMinSize}`);
  }
  const out: PckExtensions = {
    ppid: "",
    tcb: { pceSvn: 0, cpuSvn: new Uint8Array(0), cpuSvnComponents: new Uint8Array(tcbComponentSize) },
    pceid: "",
    fmspc: "",
  };
  for (const entry of entries) {
    const { oid, value } = entryOIDAndValue(sgxExt.value, entry, "SGX extension's");
    switch (oid) {
      case OidPPID:
        out.ppid = octetStringValue(sgxExt.value, value, "PPID", ppidSize);
        break;
      case OidTCB:
        out.tcb = extractTcbExtension(sgxExt.value, value);
        break;
      case OidPCEID:
        out.pceid = octetStringValue(sgxExt.value, value, "PCEID", pceIDSize);
        break;
      case OidFMSPC:
        out.fmspc = octetStringValue(sgxExt.value, value, "FMSPC", fmspcSize);
        break;
    }
  }
  return out;
}

// PCS response body types (pcs.TdxTcbInfo / pcs.QeIdentity).

export type TcbComponentStatus = string;
export const TcbComponentStatusUpToDate = "UpToDate";

const validTcbStatuses = new Set([
  "UpToDate",
  "SWHardeningNeeded",
  "ConfigurationNeeded",
  "ConfigurationAndSWHardeningNeeded",
  "OutOfDate",
  "OutOfDateConfigurationNeeded",
  "Revoked",
]);

export interface TcbComponent {
  svn: number;
  category: string;
  type: string;
}

export interface Tcb {
  sgxTcbcomponents: TcbComponent[];
  pcesvn: number;
  tdxTcbcomponents: TcbComponent[];
  isvsvn: number;
}

export interface TcbLevel {
  tcb: Tcb;
  tcbDate: string;
  tcbStatus: TcbComponentStatus;
}

export interface TdxModule {
  mrsigner: Uint8Array;
  attributes: Uint8Array;
  attributesMask: Uint8Array;
}

export interface TdxModuleIdentity {
  id: string;
  mrsigner: Uint8Array;
  attributes: Uint8Array;
  attributesMask: Uint8Array;
  tcbLevels: TcbLevel[];
}

export interface TcbInfo {
  id: string;
  version: number;
  issueDate: Date;
  nextUpdate: Date;
  fmspc: string;
  pceId: string;
  tcbType: number;
  tcbEvaluationDataNumber: number;
  tdxModule: TdxModule;
  tdxModuleIdentities: TdxModuleIdentity[];
  tcbLevels: TcbLevel[];
}

export interface TdxTcbInfo {
  tcbInfo: TcbInfo;
  signature: string;
}

export interface EnclaveIdentity {
  id: string;
  version: number;
  issueDate: Date;
  nextUpdate: Date;
  tcbEvaluationDataNumber: number;
  miscselect: Uint8Array;
  miscselectMask: Uint8Array;
  attributes: Uint8Array;
  attributesMask: Uint8Array;
  mrsigner: Uint8Array;
  isvProdID: number;
  tcbLevels: TcbLevel[];
}

export interface QeIdentity {
  enclaveIdentity: EnclaveIdentity;
  signature: string;
}

// Typed member readers mirroring encoding/json unmarshal failures: a present
// member of the wrong JSON type is an error, an absent member is the zero
// value. Unknown members are ignored (encoding/json default).

function jsonStr(obj: Record<string, unknown>, key: string): string {
  const v = obj[key];
  if (v === undefined || v === null) return "";
  if (typeof v !== "string") throw new Error(`cannot unmarshal ${key}: not a string`);
  return v;
}

function jsonInt(obj: Record<string, unknown>, key: string, min: number, max: number): number {
  const v = obj[key];
  if (v === undefined || v === null) return 0;
  if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max) {
    throw new Error(`cannot unmarshal ${key}: not an integer in range`);
  }
  return v;
}

// jsonTime mirrors time.Time unmarshalling: RFC 3339 required.
const rfc3339RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

function jsonTime(obj: Record<string, unknown>, key: string): Date {
  const v = obj[key];
  if (v === undefined || v === null) return new Date(0);
  if (typeof v !== "string" || !rfc3339RE.test(v)) {
    throw new Error(`cannot unmarshal ${key}: not an RFC 3339 time`);
  }
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) throw new Error(`cannot unmarshal ${key}: invalid time`);
  return d;
}

// jsonHexBytes mirrors pcs.HexBytes: a hex string (either case) or error.
function jsonHexBytes(obj: Record<string, unknown>, key: string): Uint8Array {
  const v = obj[key];
  if (v === undefined || v === null) return new Uint8Array(0);
  if (typeof v !== "string") throw new Error(`cannot unmarshal ${key}: not a string`);
  try {
    return decodeHex(v);
  } catch {
    throw new Error(`cannot unmarshal ${key}: not hex`);
  }
}

function jsonObj(v: unknown, what: string): Record<string, unknown> {
  if (v === undefined || v === null) return {};
  if (typeof v !== "object" || Array.isArray(v)) throw new Error(`cannot unmarshal ${what}: not an object`);
  return v as Record<string, unknown>;
}

function jsonArr(obj: Record<string, unknown>, key: string): unknown[] {
  const v = obj[key];
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) throw new Error(`cannot unmarshal ${key}: not an array`);
  return v;
}

function parseTcbComponents(obj: Record<string, unknown>, key: string): TcbComponent[] {
  return jsonArr(obj, key).map((e) => {
    const c = jsonObj(e, key);
    return {
      svn: jsonInt(c, "svn", 0, 255),
      category: jsonStr(c, "category"),
      type: jsonStr(c, "type"),
    };
  });
}

function parseTcbLevels(obj: Record<string, unknown>): TcbLevel[] {
  return jsonArr(obj, "tcbLevels").map((e) => {
    const l = jsonObj(e, "tcbLevels");
    const t = jsonObj(l["tcb"], "tcb");
    const status = l["tcbStatus"];
    let tcbStatus = "";
    if (status !== undefined && status !== null) {
      if (typeof status !== "string" || !validTcbStatuses.has(status)) {
        throw new Error(`unexpected tcb status found: ${JSON.stringify(status)}`);
      }
      tcbStatus = status;
    }
    return {
      tcb: {
        sgxTcbcomponents: parseTcbComponents(t, "sgxtcbcomponents"),
        pcesvn: jsonInt(t, "pcesvn", 0, 65535),
        tdxTcbcomponents: parseTcbComponents(t, "tdxtcbcomponents"),
        isvsvn: jsonInt(t, "isvsvn", 0, 4294967295),
      },
      tcbDate: jsonStr(l, "tcbDate"),
      tcbStatus,
    };
  });
}

function parseTdxModule(v: unknown): TdxModule {
  const m = jsonObj(v, "tdxModule");
  return {
    mrsigner: jsonHexBytes(m, "mrsigner"),
    attributes: jsonHexBytes(m, "attributes"),
    attributesMask: jsonHexBytes(m, "attributesMask"),
  };
}

// parseTdxTcbInfo decodes a TCB Info response body (Go: json.Unmarshal into
// pcs.TdxTcbInfo).
export function parseTdxTcbInfo(body: Uint8Array): TdxTcbInfo {
  let root: unknown;
  try {
    root = JSON.parse(utf8DecodeLenient(body));
  } catch (err) {
    throw new Error(`unable to unmarshal tcbInfo response: ${err instanceof Error ? err.message : String(err)}`);
  }
  const outer = jsonObj(root, "tcbInfo response");
  const info = jsonObj(outer["tcbInfo"], "tcbInfo");
  return {
    tcbInfo: {
      id: jsonStr(info, "id"),
      version: jsonInt(info, "version", 0, 255),
      issueDate: jsonTime(info, "issueDate"),
      nextUpdate: jsonTime(info, "nextUpdate"),
      fmspc: jsonStr(info, "fmspc"),
      pceId: jsonStr(info, "pceId"),
      tcbType: jsonInt(info, "tcbType", 0, 255),
      tcbEvaluationDataNumber: jsonInt(info, "tcbEvaluationDataNumber", Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER),
      tdxModule: parseTdxModule(info["tdxModule"]),
      tdxModuleIdentities: jsonArr(info, "tdxModuleIdentities").map((e) => {
        const m = jsonObj(e, "tdxModuleIdentities");
        return {
          id: jsonStr(m, "id"),
          mrsigner: jsonHexBytes(m, "mrsigner"),
          attributes: jsonHexBytes(m, "attributes"),
          attributesMask: jsonHexBytes(m, "attributesMask"),
          tcbLevels: parseTcbLevels(m),
        };
      }),
      tcbLevels: parseTcbLevels(info),
    },
    signature: jsonStr(outer, "signature"),
  };
}

// parseQeIdentity decodes a QE Identity response body (Go: json.Unmarshal
// into pcs.QeIdentity).
export function parseQeIdentity(body: Uint8Array): QeIdentity {
  let root: unknown;
  try {
    root = JSON.parse(utf8DecodeLenient(body));
  } catch (err) {
    throw new Error(`unable to unmarshal QeIdentity response: ${err instanceof Error ? err.message : String(err)}`);
  }
  const outer = jsonObj(root, "QeIdentity response");
  const id = jsonObj(outer["enclaveIdentity"], "enclaveIdentity");
  return {
    enclaveIdentity: {
      id: jsonStr(id, "id"),
      version: jsonInt(id, "version", 0, 255),
      issueDate: jsonTime(id, "issueDate"),
      nextUpdate: jsonTime(id, "nextUpdate"),
      tcbEvaluationDataNumber: jsonInt(id, "tcbEvaluationDataNumber", Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER),
      miscselect: jsonHexBytes(id, "miscselect"),
      miscselectMask: jsonHexBytes(id, "miscselectMask"),
      attributes: jsonHexBytes(id, "attributes"),
      attributesMask: jsonHexBytes(id, "attributesMask"),
      mrsigner: jsonHexBytes(id, "mrsigner"),
      isvProdID: jsonInt(id, "isvprodid", 0, 65535),
      tcbLevels: parseTcbLevels(id),
    },
    signature: jsonStr(outer, "signature"),
  };
}

// rawTopLevelMember returns the exact raw JSON text of a top-level object
// member (Go: bodyToRawMessage via map[string]json.RawMessage — last
// duplicate wins). Undefined when the member is absent.
export function rawTopLevelMember(body: Uint8Array, name: string): Uint8Array | undefined {
  const s = utf8DecodeLenient(body);
  let pos = 0;
  const skipWS = () => {
    while (pos < s.length && " \t\r\n".includes(s[pos])) pos++;
  };
  const skipString = (): string => {
    const start = pos;
    pos++; // opening quote
    while (pos < s.length) {
      if (s[pos] === "\\") pos += 2;
      else if (s[pos] === '"') {
        pos++;
        return s.slice(start, pos);
      } else pos++;
    }
    throw new Error("unexpected end of string literal");
  };
  const skipValue = (): void => {
    skipWS();
    const c = s[pos];
    if (c === '"') {
      skipString();
      return;
    }
    if (c === "{" || c === "[") {
      let depth = 0;
      while (pos < s.length) {
        const d = s[pos];
        if (d === '"') {
          skipString();
          continue;
        }
        if (d === "{" || d === "[") depth++;
        if (d === "}" || d === "]") {
          depth--;
          if (depth === 0) {
            pos++;
            return;
          }
        }
        pos++;
      }
      throw new Error("unexpected end of JSON value");
    }
    while (pos < s.length && !",}] \t\r\n".includes(s[pos])) pos++;
  };

  skipWS();
  if (s[pos] !== "{") throw new Error(`could not convert ${JSON.stringify(name)} body to raw message`);
  pos++;
  let found: Uint8Array | undefined;
  skipWS();
  if (s[pos] === "}") return found;
  for (;;) {
    skipWS();
    if (s[pos] !== '"') throw new Error(`could not convert ${JSON.stringify(name)} body to raw message`);
    const keyToken = skipString();
    const key = JSON.parse(keyToken) as string;
    skipWS();
    if (s[pos] !== ":") throw new Error(`could not convert ${JSON.stringify(name)} body to raw message`);
    pos++;
    skipWS();
    const valueStart = pos;
    skipValue();
    if (key === name) {
      found = utf8Encode(s.slice(valueStart, pos));
    }
    skipWS();
    if (s[pos] === "}") return found;
    if (s[pos] !== ",") throw new Error(`could not convert ${JSON.stringify(name)} body to raw message`);
    pos++;
  }
}
