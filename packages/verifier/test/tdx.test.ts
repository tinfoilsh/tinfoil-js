/**
 * TDX quote authentication over the shared conformance vectors: the quote
 * ABI, the PCK certificate's SGX extension, the replayed PCS collateral and
 * its statements, the TCB evaluation rules, the full authentication of every
 * quote-tdx vector, and the expectations a policy turns into.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { dangerousTestOnlyDecode } from "../conformance/testing.js";
import type { PcsResponse } from "../src/document/collateral/tdx.js";
import { toHex } from "../src/internal/bytes.js";
import type { TdxPolicy } from "../src/internal/policy/tdx.js";
import * as quote from "../src/internal/quote/quote.js";
import { parseQuote, pckChainDer } from "../src/internal/quote/tdx/abi.js";
import { assembleTdx, authenticateTdx, platformMeasurements, validateTdx, type TdxQuote } from "../src/internal/quote/tdx/authenticate.js";
import { identity } from "../src/internal/quote/tdx/identity.js";
import { pckExtensions } from "../src/internal/quote/tdx/pck.js";
import {
  checkQeTcbStatus,
  checkTcbStatus,
  collateralKey,
  crlDistributionPointUris,
  HEADER_TCB_INFO_ISSUER_CHAIN,
  indexCollateral,
  issuerChain,
  matchingTcbLevel,
  matchingTdxModuleLevel,
  memberValueBytes,
  qeIdentity,
  tcbInfo,
  type TcbInfo,
  type TcbLevel,
} from "../src/internal/quote/tdx/pcs.js";
import { parseRfc3339 } from "../src/internal/rfc3339.js";
import { parseCertificate } from "../src/internal/x509/certificate.js";
import { pemBlocks } from "../src/internal/x509/der.js";
import {
  conformanceAvailable,
  decodeDocument,
  inputBytes,
  intelPcsResponses,
  loadFixture,
  loadFixtures,
  tdxQuoteBytes,
  vectorsTitle,
  type ConformanceFixture,
} from "./helpers/conformance.js";

const withoutVectors = !conformanceAvailable();
const hex = (s: string): Uint8Array<ArrayBuffer> => new Uint8Array(Buffer.from(s.replace(/\s+/g, ""), "hex"));
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const repeat = (byte: number, n: number): Uint8Array<ArrayBuffer> => new Uint8Array(n).fill(byte);

const INTEL_QE_VENDOR_ID = "939a7233f79c4ca9940a0db3957f0607";
const SYNTH_PPID = "55".repeat(16);
const SYNTH_FMSPC = "50806f000000";

/** The captured PCS responses of a vector in the shape the verifier reads. */
function responsesOf(fixture: ConformanceFixture): PcsResponse[] {
  return intelPcsResponses(decodeDocument(fixture)).map((r) => ({
    url: r.url,
    ...(r.headers ? { headers: new Map(Object.entries(r.headers).map(([k, v]) => [k, v ?? []])) } : {}),
    body: new Uint8Array(Buffer.from(r.body_base64, "base64")),
  }));
}

function rootOf(fixture: ConformanceFixture): Uint8Array {
  return utf8(fixture.input.intel_sgx_root_pem!);
}

function clockOf(fixture: ConformanceFixture): Date {
  return fixture.input.verification_time_unix ? new Date(fixture.input.verification_time_unix * 1000) : new Date();
}

let happy: ConformanceFixture;
let happyQuote: Uint8Array;
let happyResponses: PcsResponse[];

function loadHappy(): void {
  if (happy !== undefined) return;
  happy = loadFixture("quote-tdx/tdx-happy.json");
  happyQuote = tdxQuoteBytes(decodeDocument(happy));
  happyResponses = responsesOf(happy);
}

// ---------------------------------------------------------------- rfc3339

describe("parseRfc3339", () => {
  it("accepts Z, offsets and fractions", () => {
    expect(parseRfc3339("2023-06-18T08:42:58Z", "t").toISOString()).toBe("2023-06-18T08:42:58.000Z");
    expect(parseRfc3339("2023-06-18T08:42:58.25Z", "t").getUTCMilliseconds()).toBe(250);
    expect(parseRfc3339("2023-06-18T10:42:58+02:00", "t").toISOString()).toBe("2023-06-18T08:42:58.000Z");
  });

  it("keeps years below 100 as written", () => {
    expect(parseRfc3339("0050-01-01T00:00:00Z", "t").getUTCFullYear()).toBe(50);
    expect(() => parseRfc3339("0050-02-30T00:00:00Z", "t")).toThrow(/not a real time/);
  });

  it("rejects other layouts, impossible dates and clocks", () => {
    for (const bad of ["2023-06-18 08:42:58Z", "2023-06-18t08:42:58Z", "2023-06-18T08:42:58z", "2023-06-18T08:42:58", "2023-02-30T00:00:00Z", "2023-06-18T24:00:00Z", "2023-06-18T08:60:00Z", ""]) {
      expect(() => parseRfc3339(bad, "t"), bad).toThrow(/not RFC 3339|not a real time/);
    }
  });
});

// ---------------------------------------------------------------- quote ABI

describe.skipIf(withoutVectors)(vectorsTitle("parseQuote"), () => {
  beforeAll(loadHappy);

  it("decodes the header, body and certification data of the synthetic quote", () => {
    const q = parseQuote(happyQuote);
    expect(q.header).toEqual({
      version: 4,
      attestationKeyType: 2,
      teeType: 0x81,
      pceSvn: new Uint8Array(2),
      qeSvn: new Uint8Array(2),
      qeVendorId: hex(INTEL_QE_VENDOR_ID),
      userData: new Uint8Array(20),
    });
    expect(q.body.teeTcbSvn).toEqual(hex("00030500" + "00".repeat(12)));
    expect(q.body.mrSeam).toEqual(repeat(0xaa, 48));
    expect(q.body.mrSignerSeam).toEqual(new Uint8Array(48));
    expect(q.body.seamAttributes).toEqual(new Uint8Array(8));
    expect(q.body.tdAttributes).toEqual(hex("0000004000000000"));
    expect(q.body.xfam).toEqual(hex("e71a060000000000"));
    expect(q.body.mrTd).toEqual(repeat(0x11, 48));
    expect(q.body.mrConfigId).toEqual(new Uint8Array(48));
    expect(q.body.mrOwner).toEqual(new Uint8Array(48));
    expect(q.body.mrOwnerConfig).toEqual(new Uint8Array(48));
    expect(q.body.rtmrs).toEqual([repeat(0x22, 48), repeat(0x33, 48), repeat(0x44, 48), new Uint8Array(48)]);
    expect(q.body.reportData).toEqual(repeat(0x66, 64));
    expect(q.signedBytes).toEqual(happyQuote.slice(0, 632));
    expect(q.signature).toHaveLength(64);
    expect(q.attestationKey).toHaveLength(64);
    expect(q.qeReport.raw).toHaveLength(384);
    expect(q.qeReport.mrSigner).toEqual(repeat(0xdc, 32));
    expect(q.qeReport.isvProdId).toBe(2);
    expect(q.qeReport.isvSvn).toBe(8);
    expect(q.qeReport.miscSelect).toBe(0);
    expect(q.qeReport.attributes).toEqual(hex("11" + "00".repeat(15)));
    expect(q.qeReport.mrEnclave).toEqual(repeat(0x77, 32));
    expect(q.qeReportSignature).toHaveLength(64);
    expect(q.qeAuthData).toHaveLength(0);
    expect(pckChainDer(q.pckChainPem)).toHaveLength(3);
    expect(q.extraBytes).toHaveLength(0);
  });

  it("keeps bytes after the signed data as extra bytes", () => {
    const padded = new Uint8Array([...happyQuote, 0, 0, 7]);
    expect(parseQuote(padded).extraBytes).toEqual(new Uint8Array([0, 0, 7]));
  });

  it("rejects other versions, key types and TEE types", () => {
    const patched = (at: number, ...bytes: number[]): Uint8Array => {
      const out = new Uint8Array(happyQuote);
      out.set(bytes, at);
      return out;
    };
    expect(() => parseQuote(patched(0, 5, 0))).toThrow(/unsupported TDX quote version 5/);
    expect(() => parseQuote(patched(2, 3, 0))).toThrow(/attestation key type 3/);
    expect(() => parseQuote(patched(4, 0x00, 0x00, 0x00, 0x00))).toThrow(/TEE type 0x0 is not TDX/);
    expect(() => parseQuote(patched(128 + 636, 7, 0))).toThrow(/certification data is type 7/);
  });

  it("rejects truncation and declared sizes that disagree with the bytes", () => {
    expect(() => parseQuote(happyQuote.subarray(0, 1))).toThrow(/truncated/);
    expect(() => parseQuote(happyQuote.subarray(0, 1000))).toThrow(/shorter than the minimum/);
    expect(() => parseQuote(happyQuote.subarray(0, happyQuote.length - 1))).toThrow(/declares .* bytes of signature data/);
    // A signature data size one short leaves the certification data a byte shorter than it declares.
    const short = new Uint8Array(happyQuote);
    new DataView(short.buffer).setUint32(632, new DataView(short.buffer).getUint32(632, true) - 1, true);
    expect(() => parseQuote(short)).toThrow(/certification data is .* bytes, declared/);
    const grown = new Uint8Array([...happyQuote, 0]);
    new DataView(grown.buffer).setUint32(632, new DataView(grown.buffer).getUint32(632, true) + 1, true);
    expect(() => parseQuote(grown)).toThrow(/certification data is .* bytes, declared/);
  });

  it("requires exactly three certificates in the chain", () => {
    const q = parseQuote(happyQuote);
    const [leaf] = pckChainDer(q.pckChainPem);
    expect(leaf[0]).toBe(0x30);
    expect(() => pckChainDer(q.pckChainPem.slice(0, q.pckChainPem.lastIndexOf("-----BEGIN")))).toThrow(/carries 2 certificates/);
    expect(() => pckChainDer(q.pckChainPem + q.pckChainPem)).toThrow(/carries 6 certificates/);
  });
});

// ---------------------------------------------------------------- PCK extension

describe.skipIf(withoutVectors)(vectorsTitle("pckExtensions and identity"), () => {
  beforeAll(loadHappy);

  it("reads the PPID, TCB, PCEID and FMSPC of the synthetic PCK certificate", () => {
    const [leaf] = pckChainDer(parseQuote(happyQuote).pckChainPem).map(parseCertificate);
    const ext = pckExtensions(leaf);
    expect(toHex(ext.ppid)).toBe(SYNTH_PPID);
    expect(toHex(ext.fmspc)).toBe(SYNTH_FMSPC);
    expect(toHex(ext.pceId)).toBe("0000");
    expect(ext.pceSvn).toBe(11);
    expect(ext.cpuSvn).toEqual(hex("05050202030100030000000000000000"));
    expect(ext.cpuSvnComponents).toEqual(ext.cpuSvn);
    expect(identity(leaf)).toBe(SYNTH_PPID);
  });

  it("rejects a certificate without the full extension set", () => {
    const [leaf, intermediate] = pckChainDer(parseQuote(happyQuote).pckChainPem).map(parseCertificate);
    expect(() => pckExtensions(intermediate)).toThrow(/carries 5 extensions, expected 6/);
    const noSgx = { ...leaf, extensions: [...leaf.extensions.filter((e) => !e.oid.startsWith("1.2.840.113741")), { oid: "1.2.3.4", critical: false, value: new Uint8Array() }] };
    expect(() => pckExtensions(noSgx)).toThrow(/no SGX extension/);
    const malformed = { ...leaf, extensions: leaf.extensions.map((e) => (e.oid.startsWith("1.2.840.113741") ? { ...e, value: hex("3000") } : e)) };
    expect(() => pckExtensions(malformed)).toThrow(/SGX extension has no PPID/);
  });
});

// ---------------------------------------------------------------- PCS collateral

describe("collateralKey", () => {
  it("drops the evaluation number, sorts the query and lowercases", () => {
    expect(collateralKey("https://API.trustedservices.intel.com/tdx/certification/v4/tcb?tcbEvaluationDataNumber=18&fmspc=50806F000000")).toBe(
      "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=50806f000000",
    );
    expect(collateralKey("https://a.test/pckcrl?encoding=der&ca=platform")).toBe("https://a.test/pckcrl?ca=platform&encoding=der");
    expect(collateralKey("https://a.test/qe/identity")).toBe("https://a.test/qe/identity");
    expect(() => collateralKey("not a url")).toThrow(/not a URL/);
  });

  it("indexes captured responses by key, the later capture winning", () => {
    const a: PcsResponse = { url: "https://a.test/tcb?fmspc=1&tcbEvaluationDataNumber=3", body: utf8("a") };
    const b: PcsResponse = { url: "https://a.test/tcb?fmspc=1", body: utf8("b") };
    const c = indexCollateral([a, b]);
    expect(c.get("https://a.test/tcb?fmspc=1")).toBe(b);
    expect(c.get("https://a.test/tcb?fmspc=1&tcbEvaluationDataNumber=9")).toBe(b);
    expect(c.get("https://a.test/tcb?fmspc=2")).toBeUndefined();
  });
});

describe("memberValueBytes", () => {
  it("returns the exact bytes of a top-level member's value", () => {
    const body = utf8(' { "a" : {"x":[1,2,{"y":"}"}],"s":"\\"}"} , "signature":"00" }');
    expect(new TextDecoder().decode(memberValueBytes(body, "a"))).toBe('{"x":[1,2,{"y":"}"}],"s":"\\"}"}');
    expect(new TextDecoder().decode(memberValueBytes(body, "signature"))).toBe('"00"');
    expect(() => memberValueBytes(body, "z")).toThrow(/has no "z" member/);
    expect(() => memberValueBytes(utf8("[]"), "a")).toThrow(/not an object/);
  });
});

describe.skipIf(withoutVectors)(vectorsTitle("PCS statements and chains"), () => {
  beforeAll(loadHappy);

  it("reads an issuer chain from a response header, whatever the header's case", () => {
    const response = happyResponses.find((r) => r.url.includes("/tcb?"))!;
    const chain = issuerChain(response, HEADER_TCB_INFO_ISSUER_CHAIN);
    expect(chain.signing.subjectCommonName).toBe("Intel SGX TCB Signing");
    expect(chain.root.subjectCommonName).toBe("Intel SGX Root CA");
    const lower = { ...response, headers: new Map([...response.headers!].map(([k, v]) => [k.toLowerCase(), v])) };
    expect(issuerChain(lower, HEADER_TCB_INFO_ISSUER_CHAIN).root.raw).toEqual(chain.root.raw);
  });

  it("rejects a missing, repeated, empty or short issuer chain header", () => {
    const response = happyResponses.find((r) => r.url.includes("/tcb?"))!;
    const value = response.headers!.get(HEADER_TCB_INFO_ISSUER_CHAIN)![0]!;
    const withHeader = (h: Map<string, readonly string[]>): PcsResponse => ({ ...response, headers: h });
    expect(() => issuerChain({ url: response.url, body: response.body }, HEADER_TCB_INFO_ISSUER_CHAIN)).toThrow(/has no Tcb-Info-Issuer-Chain header/);
    expect(() => issuerChain(withHeader(new Map([[HEADER_TCB_INFO_ISSUER_CHAIN, [value, value]]])), HEADER_TCB_INFO_ISSUER_CHAIN)).toThrow(/one value, found 2/);
    expect(() => issuerChain(withHeader(new Map([[HEADER_TCB_INFO_ISSUER_CHAIN, [""]]])), HEADER_TCB_INFO_ISSUER_CHAIN)).toThrow(/is empty/);
    const onlyRoot = value.slice(value.indexOf(encodeURIComponent("-----BEGIN"), 10));
    expect(() => issuerChain(withHeader(new Map([[HEADER_TCB_INFO_ISSUER_CHAIN, [onlyRoot]]])), HEADER_TCB_INFO_ISSUER_CHAIN)).toThrow(/carries 1 certificates, expected 2/);
    expect(() => issuerChain(withHeader(new Map([[HEADER_TCB_INFO_ISSUER_CHAIN, ["%zz"]]])), HEADER_TCB_INFO_ISSUER_CHAIN)).toThrow(/not URL-encoded/);
  });

  it("finds the root CRL URI in the root certificate's distribution points", () => {
    const response = happyResponses.find((r) => r.url.includes("/qe/identity"))!;
    const { root, signing } = issuerChain(response, "Sgx-Enclave-Identity-Issuer-Chain");
    expect(crlDistributionPointUris(root)).toEqual(["https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"]);
    expect(crlDistributionPointUris(signing)).toEqual(["https://certificates.trustedservices.intel.com/IntelSGXPCKPlatform.crl"]);
    expect(crlDistributionPointUris({ ...root, extensions: [] })).toEqual([]);
  });

  it("decodes the TCB info and its signed bytes", () => {
    const { statement } = tcbInfo(indexCollateral(happyResponses), SYNTH_FMSPC);
    expect(statement.id).toBe("TDX");
    expect(statement.version).toBe(3);
    expect(statement.fmspc).toBe(SYNTH_FMSPC);
    expect(statement.pceId).toBe("0000");
    expect(statement.tcbEvaluationDataNumber).toBe(18n);
    expect(statement.issueDate.toISOString()).toBe("2023-06-18T08:42:58.000Z");
    expect(statement.tdxModule.mrSigner).toEqual(new Uint8Array(48));
    expect(statement.tdxModule.attributesMask).toEqual(repeat(0xff, 8));
    expect(statement.tdxModuleIdentities.map((m) => m.id)).toEqual(["TDX_03"]);
    expect(statement.tcbLevels).toHaveLength(1);
    expect(statement.tcbLevels[0].pceSvn).toBe(11);
    expect(statement.tcbLevels[0].status).toBe("UpToDate");
    expect(statement.tcbLevels[0].sgxComponents.map((c) => c.svn)).toEqual([5, 5, 2, 2, 3, 1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0]);
    expect(statement.signature).toHaveLength(64);
    const body = new TextDecoder().decode(happyResponses.find((r) => r.url.includes("/tcb?"))!.body);
    expect(new TextDecoder().decode(statement.signed)).toBe(body.slice(body.indexOf('{"tcbInfo":') + 11, body.lastIndexOf(',"signature"')));
  });

  it("decodes the QE identity", () => {
    const { statement } = qeIdentity(indexCollateral(happyResponses));
    expect(statement.id).toBe("TD_QE");
    expect(statement.version).toBe(2);
    expect(statement.mrSigner).toEqual(repeat(0xdc, 32));
    expect(statement.isvProdId).toBe(2);
    expect(statement.miscSelectMask).toEqual(repeat(0xff, 4));
    expect(statement.attributesMask).toEqual(hex("FBFFFFFFFFFFFFFF0000000000000000"));
    expect(statement.tcbLevels.map((l) => [l.isvSvn, l.status])).toEqual([[8, "UpToDate"]]);
    expect(statement.tcbEvaluationDataNumber).toBe(18n);
  });

  it("rejects a statement that is missing, unparseable or malformed", () => {
    const edited = (edit: (text: string) => string): ReturnType<typeof indexCollateral> =>
      indexCollateral(
        happyResponses.map((r) => (r.url.includes("/tcb?") ? { ...r, body: utf8(edit(new TextDecoder().decode(r.body))) } : r)),
      );
    expect(() => tcbInfo(indexCollateral(happyResponses.filter((r) => !r.url.includes("/tcb?"))), SYNTH_FMSPC)).toThrow(/no captured response for the TCB info/);
    expect(() => tcbInfo(edited(() => ""), SYNTH_FMSPC)).toThrow(/response is empty/);
    expect(() => tcbInfo(edited((t) => t.slice(1)), SYNTH_FMSPC)).toThrow(/tcbInfo response/);
    expect(() => tcbInfo(edited((t) => t.replace('"tcbInfo"', '"other"')), SYNTH_FMSPC)).toThrow(/has no "tcbInfo" member/);
    expect(() => tcbInfo(edited((t) => t.replace('"version":3', '"version":3.0')), SYNTH_FMSPC)).toThrow(/not an integer/);
    expect(() => tcbInfo(edited((t) => t.replace('"tcbEvaluationDataNumber":18', '"tcbEvaluationDataNumber":-1')), SYNTH_FMSPC)).toThrow(/into uint64/);
    expect(() => tcbInfo(edited((t) => t.replace('"tcbStatus":"UpToDate"', '"tcbStatus":"Fine"')), SYNTH_FMSPC)).toThrow(/unexpected tcb status "Fine"/);
    expect(() => tcbInfo(edited((t) => t.replace('"issueDate":"2023-06-18T08:42:58Z"', '"issueDate":null')), SYNTH_FMSPC)).toThrow(/states no issueDate/);
    expect(() => tcbInfo(edited((t) => t.replace(/"signature":"[0-9a-f]+"/, '"signature":"0011"')), SYNTH_FMSPC)).toThrow(/signature is 2 bytes/);
    expect(() => tcbInfo(edited((t) => t.replace('"mrsigner":"0000', '"mrsigner":"zz00')), SYNTH_FMSPC)).toThrow(/mrsigner is not hex/);
  });
});

// ---------------------------------------------------------------- TCB evaluation

describe("TCB level evaluation", () => {
  const comps = (...svns: number[]): { svn: number }[] => svns.map((svn) => ({ svn }));
  const level = (sgx: number[], pce: number, tdx: number[], status = "UpToDate"): TcbLevel => ({
    sgxComponents: comps(...sgx),
    tdxComponents: comps(...tdx),
    pceSvn: pce,
    isvSvn: 0,
    status,
  });
  const sixteen = (...head: number[]): number[] => [...head, ...new Array<number>(16 - head.length).fill(0)];
  const pck = { ppid: new Uint8Array(16), cpuSvn: new Uint8Array(16), cpuSvnComponents: hex("05050202030100030000000000000000"), pceSvn: 11, pceId: new Uint8Array(2), fmspc: new Uint8Array(6) };
  const body = (teeTcbSvn: Uint8Array) => ({ teeTcbSvn }) as Parameters<typeof matchingTcbLevel>[1];

  it("picks the first level every component meets, skipping the module bytes of a versioned TDX module", () => {
    const levels = [level(sixteen(5, 5, 2, 2, 3, 1, 0, 3), 11, sixteen(3, 0, 5)), level(sixteen(1), 1, sixteen(0), "OutOfDate")];
    expect(matchingTcbLevel(levels, body(hex("00030500" + "00".repeat(12))), pck)).toBe(levels[0]);
    // With byte 1 zero the first two TEE TCB SVN bytes count, and 0 < 3 fails the first level.
    expect(matchingTcbLevel(levels, body(hex("00000500" + "00".repeat(12))), pck)).toBe(levels[1]);
    expect(matchingTcbLevel(levels, body(hex("00030400" + "00".repeat(12))), pck)).toBe(levels[1]);
    expect(matchingTcbLevel(levels, body(hex("00030500" + "00".repeat(12))), { ...pck, pceSvn: 10 })).toBe(levels[1]);
    expect(() => matchingTcbLevel(levels.slice(0, 1), body(hex("00030500" + "00".repeat(12))), { ...pck, pceSvn: 10 })).toThrow(/no TCB level/);
    // A level whose component list is not sixteen long never matches.
    expect(() => matchingTcbLevel([level([5], 11, sixteen(3, 0, 5))], body(hex("00030500" + "00".repeat(12))), pck)).toThrow(/no TCB level/);
  });

  const module = (id: string, levels: TcbLevel[], mrSigner = new Uint8Array(48), attributes = new Uint8Array(8), attributesMask = repeat(0xff, 8)) => ({
    id,
    mrSigner,
    attributes,
    attributesMask,
    tcbLevels: levels,
  });

  it("resolves the TDX module identity by version and ISV SVN", () => {
    const identities = [
      module("TDX_03", [{ ...level([], 0, []), isvSvn: 2 }, { ...level([], 0, [], "OutOfDate"), isvSvn: 0 }]),
      module("TDX_04", [{ ...level([], 0, []), isvSvn: 0 }]),
    ];
    expect(matchingTdxModuleLevel(identities, hex("02030000" + "00".repeat(12))).level.status).toBe("UpToDate");
    expect(matchingTdxModuleLevel(identities, hex("01030000" + "00".repeat(12))).level.status).toBe("OutOfDate");
    expect(matchingTdxModuleLevel(identities, hex("01040000" + "00".repeat(12))).identity.id).toBe("TDX_04");
    expect(() => matchingTdxModuleLevel(identities, hex("00050000" + "00".repeat(12)))).toThrow(/no TDX module identity TDX_05/);
    expect(() => matchingTdxModuleLevel([module("TDX_03", [{ ...level([], 0, []), isvSvn: 9 }])], hex("02030000" + "00".repeat(12)))).toThrow(/ISV SVN 2/);
  });

  it("requires the platform level, the module identity and the module level to agree with the quote", () => {
    const tee = { teeTcbSvn: hex("00030500" + "00".repeat(12)), mrSignerSeam: new Uint8Array(48), seamAttributes: new Uint8Array(8) } as Parameters<typeof checkTcbStatus>[1];
    const info = (status: string, identity = module("TDX_03", [{ ...level([], 0, []), isvSvn: 0 }])): TcbInfo =>
      ({ tcbLevels: [level(sixteen(5, 5, 2, 2, 3, 1, 0, 3), 11, sixteen(3, 0, 5), status)], tdxModuleIdentities: [identity] }) as unknown as TcbInfo;
    const moduleLevel = (status: string) => module("TDX_03", [{ ...level([], 0, [], status), isvSvn: 0 }]);
    expect(() => checkTcbStatus(info("UpToDate"), tee, pck)).not.toThrow();
    expect(() => checkTcbStatus(info("SWHardeningNeeded"), tee, pck)).toThrow(/TCB status is SWHardeningNeeded/);
    expect(() => checkTcbStatus(info("UpToDate", moduleLevel("Revoked")), tee, pck)).toThrow(/TDX module TCB status is Revoked/);
    // The selected identity must describe the module: signer, and attributes under its mask.
    const flagged = { ...tee, seamAttributes: hex("0000000000000080") };
    expect(() => checkTcbStatus(info("UpToDate"), flagged, pck)).toThrow(/SEAMATTRIBUTES under the mask are not TDX module identity TDX_03's attributes/);
    const unmasked = module("TDX_03", [{ ...level([], 0, []), isvSvn: 0 }], new Uint8Array(48), new Uint8Array(8), hex("ffffffffffffff7f"));
    expect(() => checkTcbStatus(info("UpToDate", unmasked), flagged, pck)).not.toThrow();
    expect(() => checkTcbStatus(info("UpToDate", module("TDX_03", [{ ...level([], 0, []), isvSvn: 0 }], repeat(1, 48))), tee, pck)).toThrow(/MRSIGNERSEAM is not TDX module identity TDX_03's signer/);
    expect(() => checkTcbStatus(info("UpToDate", module("TDX_03", [{ ...level([], 0, []), isvSvn: 0 }], new Uint8Array(47))), tee, pck)).toThrow(/of the module's size/);
    // An unversioned module (byte 1 zero) consults no module identity.
    const unversioned = { ...info("UpToDate", moduleLevel("Revoked")), tcbLevels: [level(sixteen(5, 5, 2, 2, 3, 1, 0, 3), 11, sixteen(0, 0, 5))] } as TcbInfo;
    expect(() => checkTcbStatus(unversioned, { ...tee, teeTcbSvn: hex("00000500" + "00".repeat(12)) }, pck)).not.toThrow();
  });

  it("judges the QE by the first level its ISV SVN meets", () => {
    const levels = [{ ...level([], 0, []), isvSvn: 8 }, { ...level([], 0, [], "OutOfDate"), isvSvn: 2 }];
    const report = (isvSvn: number) => ({ isvSvn }) as Parameters<typeof checkQeTcbStatus>[1];
    expect(() => checkQeTcbStatus(levels, report(8))).not.toThrow();
    expect(() => checkQeTcbStatus(levels, report(9))).not.toThrow();
    expect(() => checkQeTcbStatus(levels, report(5))).toThrow(/QE TCB status is OutOfDate/);
    expect(() => checkQeTcbStatus(levels, report(1))).toThrow(/no QE identity TCB level/);
  });
});

// ---------------------------------------------------------------- authentication

/** Why each reject vector fails; a vector failing for another reason leaves its rule untested. */
const QUOTE_REJECTIONS: Readonly<Record<string, RegExp>> = {
  "t1-quote-version": /unsupported TDX quote version/,
  "t21-qe-mrsigner": /QE MRSIGNER is not the QE identity's/,
  "t21-signature": /quote signature does not verify/,
  "t22-pcesvn": /no TCB level in the TCB info matches/,
  "t24-crl-expired": /revocation list is not current/,
  "t24-crl-not-yet-valid": /revocation list is not current/,
  "t24-missing-pcs": /no intel-pcs endorsement collateral/,
  "t24-qe-identity-issued-later": /enclaveIdentity is not yet valid/,
  "t24-tcb-info-issued-later": /tcbInfo is not yet valid/,
  "t25-wrong-root": /does not end in a trusted root/,
  "t3-extra-bytes": /non-zero bytes after the signed data/,
  "t3-reserved-bytes": /non-zero reserved bytes/,
  "t8-mr-signer-seam": /MRSIGNERSEAM is not the TCB info's/,
  "t9-seam-attributes": /SEAMATTRIBUTES under the TCB info's mask/,
};

describe.skipIf(withoutVectors)(vectorsTitle("quote.authenticate over the quote-tdx vectors"), () => {
  for (const fixture of withoutVectors ? [] : loadFixtures("quote-tdx")) {
    const { expected } = fixture;
    it(`${fixture.id}: ${expected.accepted ? "accepts" : "rejects"}`, async () => {
      const doc = await dangerousTestOnlyDecode(inputBytes(fixture, "document_b64"));
      const run = quote.authenticate(doc.cpuEvidence(), doc.cpuEndorsements(), clockOf(fixture), { dangerousTestOnlyRoots: { intel: rootOf(fixture) } });
      if (expected.accepted) {
        const q = await run;
        expect(q.platform).toBe("tdx");
        expect(q.identity).toBe(SYNTH_PPID);
        expect(q.measurement).toEqual({ platform: "tdx", mrtd: repeat(0x11, 48), rtmr0: repeat(0x22, 48), rtmr1: repeat(0x33, 48), rtmr2: repeat(0x44, 48), rtmr3: new Uint8Array(48) });
        expect(q.evidence.report).toEqual(doc.cpuEvidence().report);
        expect(q.tdx?.tcbEvaluationDataNumber).toBe(18n);
        expect(q.sev).toBeUndefined();
      } else {
        const reason = QUOTE_REJECTIONS[fixture.id];
        expect(reason, `no expected reason for vector ${fixture.id}`).toBeDefined();
        await expect(run).rejects.toThrow(reason);
      }
    });
  }
});

describe.skipIf(withoutVectors)(vectorsTitle("authenticateTdx"), () => {
  beforeAll(loadHappy);
  const now = new Date("2025-06-01T00:00:00Z");
  const authenticate = (q = happyQuote, pcs = happyResponses, at = now, root = rootOf(happy)): Promise<TdxQuote> =>
    authenticateTdx({ quote: q, pcs }, at, { dangerousTestOnlyRoot: root });

  it("accepts the synthetic quote under its synthetic root and reports its registers", async () => {
    const q = await authenticate();
    expect(q.identity).toBe(SYNTH_PPID);
    expect(platformMeasurements(q)).toEqual({ mrtd: "11".repeat(48), rtmr0: "22".repeat(48) });
    expect(q.tcbEvaluationDataNumber).toBe(18n);
    expect(q.quote.header.version).toBe(4);
  });

  it("rejects the synthetic chain under the embedded Intel root and an unusable injected root", async () => {
    await expect(authenticateTdx({ quote: happyQuote, pcs: happyResponses }, now)).rejects.toThrow(/does not end in a trusted root/);
    await expect(authenticate(happyQuote, happyResponses, now, utf8("no certificate here"))).rejects.toThrow(/carries no certificate/);
    await expect(authenticate(happyQuote, happyResponses, now, utf8("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))).rejects.toThrow(/Intel SGX root certificate/);
  });

  it("requires a valid clock", async () => {
    await expect(authenticate(happyQuote, happyResponses, new Date(NaN))).rejects.toThrow(/verification time is required/);
  });

  it("rejects when any captured response is missing", async () => {
    const without = (path: RegExp): PcsResponse[] => happyResponses.filter((r) => !path.test(r.url));
    await expect(authenticate(happyQuote, without(/\/tcb\?/))).rejects.toThrow(/no captured response for the TCB info/);
    await expect(authenticate(happyQuote, without(/qe\/identity/))).rejects.toThrow(/no captured response for the QE identity/);
    await expect(authenticate(happyQuote, without(/pckcrl/))).rejects.toThrow(/no captured response for the PCK CRL/);
    await expect(authenticate(happyQuote, without(/IntelSGXRootCA/))).rejects.toThrow(/no captured response for the root CA CRL/);
    await expect(authenticate(happyQuote, [])).rejects.toThrow(/no captured response/);
  });

  it("looks the root CA CRL up by the trusted root's own distribution point", async () => {
    const [root] = pemBlocks(new TextDecoder().decode(rootOf(happy)), "CERTIFICATE").map(parseCertificate);
    const [uri] = crlDistributionPointUris(root);
    expect(uri).toMatch(/IntelSGXRootCA/);
    // A capture under any other URL does not stand in for it, whatever the collateral's issuer chains point at.
    const moved = happyResponses.map((r) => (r.url === uri ? { ...r, url: uri.replace("IntelSGXRootCA", "Elsewhere") } : r));
    await expect(authenticate(happyQuote, moved)).rejects.toThrow(new RegExp(`no captured response for the root CA CRL \\(${uri.replace(/[.?+]/g, "\\$&")}\\)`));
  });

  it("rejects a tampered quote body, signature, QE report signature or key binding", async () => {
    const flip = (at: number): Uint8Array => {
      const out = new Uint8Array(happyQuote);
      out[at] ^= 1;
      return out;
    };
    await expect(authenticate(flip(48 + 0x88))).rejects.toThrow(/quote signature does not verify/); // MRTD
    await expect(authenticate(flip(636))).rejects.toThrow(/quote signature does not verify/); // signature r
    await expect(authenticate(flip(636 + 64))).rejects.toThrow(/does not bind the attestation key/); // attestation key X
    await expect(authenticate(flip(636 + 128 + 6))).rejects.toThrow(/QE report signature does not verify/); // QE report CPUSVN
    await expect(authenticate(flip(636 + 128 + 6 + 384))).rejects.toThrow(/QE report signature does not verify/); // QE report signature
  });

  it("rejects a statement whose signed bytes or signer changed", async () => {
    const edited = (path: RegExp, edit: (text: string) => string): PcsResponse[] =>
      happyResponses.map((r) => (path.test(r.url) ? { ...r, body: utf8(edit(new TextDecoder().decode(r.body))) } : r));
    await expect(authenticate(happyQuote, edited(/\/tcb\?/, (t) => t.replace('"pceId":"0000"', '"pceId":"0001"')))).rejects.toThrow(/tcbInfo signature does not verify/);
    await expect(authenticate(happyQuote, edited(/qe\/identity/, (t) => t.replace('"isvprodid":2', '"isvprodid":3')))).rejects.toThrow(/enclaveIdentity signature does not verify/);
    // Swapping the two chain headers leaves each statement signed by the same key, so only the roles move; a different root rejects.
    const tcb = happyResponses.find((r) => r.url.includes("/tcb?"))!;
    const swapped = happyResponses.map((r) => (r.url.includes("/tcb?") ? { ...r, headers: new Map([[HEADER_TCB_INFO_ISSUER_CHAIN, [encodeURIComponent(happy.input.intel_sgx_root_pem! + happy.input.intel_sgx_root_pem!)]]]) } : r));
    await expect(authenticate(happyQuote, swapped)).rejects.toThrow(/is not the expected "Intel SGX TCB Signing"/);
    expect(tcb.headers?.size).toBe(1);
  });

  it("rejects a statement past its next update", async () => {
    await expect(authenticate(happyQuote, happyResponses, new Date("2030-08-01T00:00:00Z"))).rejects.toThrow(/not valid at|past its next update|not current/);
  });
});

// ---------------------------------------------------------------- expectations

describe.skipIf(withoutVectors)(vectorsTitle("assembleTdx and validateTdx"), () => {
  beforeAll(loadHappy);
  const policy: TdxPolicy = {
    qeVendorId: INTEL_QE_VENDOR_ID,
    minimumTeeTcbSvn: "00030500" + "00".repeat(12),
    mrSeam: "aa".repeat(48),
    tdAttributes: "0000004000000000",
    xfam: "e71a060000000000",
    minimumTcbEvaluationDataNumber: 18n,
  };
  let q: TdxQuote;
  beforeAll(async () => {
    q = await authenticateTdx({ quote: happyQuote, pcs: happyResponses }, new Date("2025-06-01T00:00:00Z"), { dangerousTestOnlyRoot: rootOf(happy) });
  });
  const expectations = (p: TdxPolicy = policy, mrConfigId = new Uint8Array(48)) => assembleTdx(p, q, q.measurement, q.quote.body.reportData, mrConfigId);

  it("validates the authenticated quote against expectations assembled from its policy", () => {
    const e = expectations();
    expect(e.mrOwner).toEqual(new Uint8Array(48));
    expect(e.minimumTcbEvaluationDataNumber).toBe(18n);
    expect(() => validateTdx(e, q)).not.toThrow();
  });

  it("rejects an invalid policy and ill-sized inputs", () => {
    expect(() => expectations({ ...policy, mrSeam: "aa" })).toThrow(/mr_seam/);
    expect(() => expectations({ ...policy, minimumTcbEvaluationDataNumber: undefined })).toThrow(/minimum_tcb_evaluation_data_number is required/);
    expect(() => assembleTdx(policy, q, q.measurement, new Uint8Array(63), new Uint8Array(48))).toThrow(/REPORT_DATA must be 64 bytes/);
    expect(() => expectations(policy, new Uint8Array(47))).toThrow(/MRCONFIGID must be 48 bytes/);
  });

  it("rejects every field that differs from the quote", () => {
    const field = (change: (e: ReturnType<typeof expectations>) => ReturnType<typeof expectations>, message: RegExp): void => {
      expect(() => validateTdx(change(expectations()), q)).toThrow(message);
    };
    field((e) => ({ ...e, qeVendorId: new Uint8Array(16) }), /QE_VENDOR_ID/);
    field((e) => ({ ...e, mrSeam: new Uint8Array(48) }), /MR_SEAM/);
    field((e) => ({ ...e, tdAttributes: new Uint8Array(8) }), /TD_ATTRIBUTES/);
    field((e) => ({ ...e, xfam: new Uint8Array(8) }), /XFAM/);
    field((e) => ({ ...e, measurement: { ...e.measurement, mrtd: new Uint8Array(48) } }), /MR_TD/);
    field((e) => ({ ...e, measurement: { ...e.measurement, rtmr3: repeat(1, 48) } }), /RTMR\[3\]/);
    field((e) => ({ ...e, mrConfigId: repeat(1, 48) }), /MR_CONFIG_ID/);
    field((e) => ({ ...e, mrOwner: repeat(1, 48) }), /MR_OWNER /);
    field((e) => ({ ...e, mrOwnerConfig: repeat(1, 48) }), /MR_OWNER_CONFIG/);
    field((e) => ({ ...e, reportData: new Uint8Array(64) }), /REPORT_DATA/);
    field((e) => ({ ...e, minimumTeeTcbSvn: hex("00030600" + "00".repeat(12)) }), /TEE TCB SVN .* below the required minimum/);
    field((e) => ({ ...e, minimumTcbEvaluationDataNumber: 19n }), /tcbEvaluationDataNumber 18 is below the policy minimum 19/);
    expect(() => validateTdx({ ...expectations(), minimumTeeTcbSvn: hex("00030400" + "00".repeat(12)) }, q)).not.toThrow();
  });

  it("rejects XFAM and TD attributes outside the fixed bit masks even when the policy matches them", () => {
    const withBody = (patch: Partial<typeof q.quote.body>): TdxQuote => ({ ...q, quote: { ...q.quote, body: { ...q.quote.body, ...patch } } });
    const xfamClearing = withBody({ xfam: hex("e41a060000000000") });
    expect(() => validateTdx({ ...expectations(), xfam: xfamClearing.quote.body.xfam }, xfamClearing)).toThrow(/XFAM .* clears required bits/);
    const xfamExtra = withBody({ xfam: hex("e71a060000000080") });
    expect(() => validateTdx({ ...expectations(), xfam: xfamExtra.quote.body.xfam }, xfamExtra)).toThrow(/XFAM .* sets bits outside/);
    const attrs = withBody({ tdAttributes: hex("0200004000000000") });
    expect(() => validateTdx({ ...expectations(), tdAttributes: attrs.quote.body.tdAttributes }, attrs)).toThrow(/TD attributes .* set bits outside/);
    const debug = withBody({ tdAttributes: hex("0100004000000000") });
    expect(() => validateTdx({ ...expectations(), tdAttributes: debug.quote.body.tdAttributes }, debug)).not.toThrow();
  });
});
