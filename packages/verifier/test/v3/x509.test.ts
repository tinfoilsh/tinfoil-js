/**
 * Tests for the x509 layer: strict DER decoding, certificate parsing and
 * signature verification, chain verification, and revocation lists.
 *
 * DER rules are exercised on hand-built bytes. Certificates and CRLs come
 * from the embedded AMD and Intel trust material, a local RSA PKCS#1 test
 * certificate, and the shared tinfoil-conformance vectors (see
 * helpers/conformance.ts for where they are read from): the captured
 * production AMD VCEK/ASK/ARK/CRL set of the real-frozen document, and the
 * synthetic quote-sev and quote-tdx sets whose verdict depends only on this
 * layer (CRL windows, revoked issuer, wrong root). The suites that need the
 * vectors are skipped when the checkout is not available.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import {
  basicConstraints,
  extension,
  parseCertificate,
  spkiFingerprint,
  verifyCertificateSignature,
  verifyChain,
  X509Error,
  type Certificate,
} from "../../src/v3/internal/x509/certificate.js";
import { isRevoked, parseRevocationList, verifyRevocationList } from "../../src/v3/internal/x509/crl.js";
import {
  bitString,
  boolean,
  children,
  decode,
  DerError,
  ecdsaSignatureToRaw,
  integer,
  oid,
  pemBlocks,
  time,
} from "../../src/v3/internal/x509/der.js";
import { AMD_GENOA_CERT_CHAIN_PEM } from "../../src/v3/trust/amd-genoa-chain.js";
import { AMD_TURIN_CERT_CHAIN_PEM } from "../../src/v3/trust/amd-turin-chain.js";
import { INTEL_SGX_ROOT_CA_PEM } from "../../src/v3/trust/intel-sgx-root.js";
import { amdMaterial, conformanceAvailable, intelMaterial, loadFixture, vectorsTitle, type AmdMaterial, type IntelMaterial } from "./helpers/conformance.js";

// ---------------------------------------------------------------- helpers

const hex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s.replace(/\s+/g, ""), "hex"));
const b64 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "base64"));
const ascii = (s: string): Uint8Array => new TextEncoder().encode(s);

/** DER length octets in minimal form. */
function len(n: number): number[] {
  if (n < 0x80) return [n];
  const out: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) out.unshift(v & 0xff);
  return [0x80 | out.length, ...out];
}

/** One TLV from a tag byte and content bytes. */
function tlv(tag: number, ...content: (Uint8Array | number[])[]): Uint8Array {
  const body = content.flatMap((c) => Array.from(c));
  return new Uint8Array([tag, ...len(body.length), ...body]);
}
const seq = (...parts: Uint8Array[]): Uint8Array => tlv(0x30, ...parts);
const int = (...bytes: number[]): Uint8Array => tlv(0x02, bytes);
const utcTime = (s: string): Uint8Array => tlv(0x17, ascii(s));

const rsaPkcs1Pem = readFileSync(new URL("./fixtures/x509/rsa-pkcs1-selfsigned.pem", import.meta.url), "utf8");

const withoutVectors = !conformanceAvailable();

// The conformance material: the production set of the real-frozen document
// and the synthetic quote-sev and quote-tdx sets, by vector name. They are
// read in beforeAll of the suites that use them (not at import time) so a
// missing checkout only skips those.
const AMD_SYNTHETIC = ["sev-happy", "s26-revoked-ask", "struct-crl-expired", "struct-crl-not-yet-valid", "struct-crl-at-this-update", "struct-bad-chain", "s26-wrong-root"];
const INTEL_SYNTHETIC = ["tdx-happy", "t24-crl-expired", "t24-crl-not-yet-valid", "t24-crl-at-this-update", "t25-wrong-root"];

let amdReal: AmdMaterial & { verification_time_unix: number };
let amdSynthetic: Record<string, AmdMaterial>;
let intelSynthetic: Record<string, IntelMaterial>;

function loadMaterial(): void {
  if (amdReal !== undefined) return;
  const real = amdMaterial(loadFixture("real-frozen/real-sev-inference-tinfoil.json"));
  if (real.verification_time_unix === undefined) throw new Error("real-frozen vector states no verification time");
  amdReal = { ...real, verification_time_unix: real.verification_time_unix };
  amdSynthetic = Object.fromEntries(AMD_SYNTHETIC.map((name) => [name, amdMaterial(loadFixture(`quote-sev/${name}.json`))]));
  intelSynthetic = Object.fromEntries(INTEL_SYNTHETIC.map((name) => [name, intelMaterial(loadFixture(`quote-tdx/${name}.json`))]));
}

const certs = (pem: string): Certificate[] => pemBlocks(pem, "CERTIFICATE").map(parseCertificate);
const unix = (s: number): Date => new Date(s * 1000);

/** The leaf, intermediate(s) and root of an AMD set, leaf first. */
function amdChain(set: AmdMaterial): Certificate[] {
  return [parseCertificate(b64(set.vcek_der_base64)), ...certs(set.cert_chain_pem)];
}

/** A copy of `cert` with one byte of a field flipped, re-parsed. */
function tamper(cert: Certificate, field: Uint8Array, index = 0): Certificate {
  const raw = new Uint8Array(cert.raw);
  const offset = field.byteOffset - cert.raw.byteOffset + index;
  raw[offset] ^= 0x01;
  return parseCertificate(raw);
}

const [genoaAsk, genoaArk] = certs(AMD_GENOA_CERT_CHAIN_PEM);
const [turinAsk, turinArk] = certs(AMD_TURIN_CERT_CHAIN_PEM);
const [intelRoot] = certs(INTEL_SGX_ROOT_CA_PEM);

// ---------------------------------------------------------------- der.decode

describe("der.decode", () => {
  it("decodes a short-form element with raw and value views", () => {
    const e = decode(hex("02 01 05"));
    expect(e.tagClass).toBe(0);
    expect(e.constructed).toBe(false);
    expect(e.tag).toBe(2);
    expect(Array.from(e.value)).toEqual([5]);
    expect(Array.from(e.raw)).toEqual([2, 1, 5]);
    expect(integer(e)).toBe(5n);
  });

  it("rejects empty input, trailing bytes and truncation", () => {
    expect(() => decode(new Uint8Array())).toThrow(DerError);
    expect(() => decode(hex("02 01 05 00"))).toThrow(/trailing/);
    expect(() => decode(hex("02 02 05"))).toThrow(DerError);
    expect(() => decode(hex("02"))).toThrow(DerError);
  });

  it("accepts a minimal long-form length", () => {
    const body = new Uint8Array(128).fill(0xaa);
    const e = decode(tlv(0x04, body));
    expect(e.raw.length).toBe(131);
    expect(e.value).toEqual(body);
  });

  it("rejects a long-form length that fits the short form", () => {
    expect(() => decode(hex("04 81 05 01 02 03 04 05"))).toThrow(/minimal form/);
  });

  it("rejects a length with a leading zero octet", () => {
    const body = new Uint8Array(128).fill(0xaa);
    expect(() => decode(new Uint8Array([0x04, 0x82, 0x00, 0x80, ...body]))).toThrow(/minimal form/);
  });

  it("rejects the indefinite length form", () => {
    expect(() => decode(hex("30 80 02 01 01 00 00"))).toThrow(DerError);
  });

  it("rejects long-form tag numbers", () => {
    expect(() => decode(hex("1f 81 01 01 00"))).toThrow(DerError);
  });

  it("decodes SEQUENCE children in order and rejects children that overrun", () => {
    const kids = children(decode(hex("30 06 02 01 01 02 01 02")));
    expect(kids.map(integer)).toEqual([1n, 2n]);
    expect(() => children(decode(hex("02 01 01")))).toThrow(/no children/);
    expect(() => decode(hex("30 03 02 01"))).toThrow(DerError);
    expect(() => decode(hex("30 04 02 03 01"))).toThrow(DerError);
  });

  it("rejects constructed encodings of primitive types and primitive SEQUENCEs", () => {
    expect(() => decode(hex("24 03 04 01 aa"))).toThrow(/constructed encoding/);
    expect(() => decode(hex("10 00"))).toThrow(/must be constructed/);
  });

  it("rejects a non-minimal encoding nested anywhere in the tree", () => {
    expect(() => decode(hex("30 04 02 02 00 05"))).toThrow(/INTEGER/);
    expect(() => decode(hex("30 05 30 03 01 01 01"))).toThrow(/BOOLEAN/);
  });
});

describe("der INTEGER", () => {
  it("accepts a leading zero only when the next byte has its high bit set", () => {
    expect(integer(decode(hex("02 02 00 80")))).toBe(128n);
    expect(integer(decode(hex("02 01 7f")))).toBe(127n);
    expect(integer(decode(hex("02 09 00 ff ff ff ff ff ff ff ff")))).toBe((1n << 64n) - 1n);
  });

  it("rejects redundant 0x00 and 0xFF sign bytes and empty contents", () => {
    expect(() => decode(hex("02 02 00 05"))).toThrow(/minimally/);
    expect(() => decode(hex("02 02 ff 80"))).toThrow(/minimally/);
    expect(() => decode(hex("02 00"))).toThrow(/no content/);
  });

  it("rejects negative values and non-INTEGER tags", () => {
    expect(() => integer(decode(hex("02 01 ff")))).toThrow(/negative/);
    expect(() => integer(decode(hex("04 01 01")))).toThrow(/expected INTEGER/);
  });
});

describe("der BOOLEAN", () => {
  it("accepts exactly 0x00 and 0xFF", () => {
    expect(boolean(decode(hex("01 01 ff")))).toBe(true);
    expect(boolean(decode(hex("01 01 00")))).toBe(false);
  });

  it("rejects other values and lengths", () => {
    expect(() => decode(hex("01 01 01"))).toThrow(/BOOLEAN/);
    expect(() => decode(hex("01 02 00 00"))).toThrow(/BOOLEAN/);
    expect(() => decode(hex("01 00"))).toThrow(/BOOLEAN/);
    expect(() => boolean(decode(hex("02 01 01")))).toThrow(/expected BOOLEAN/);
  });
});

describe("der BIT STRING", () => {
  it("returns the bytes when no bits are unused", () => {
    expect(Array.from(bitString(decode(hex("03 03 00 ff 01"))))).toEqual([0xff, 0x01]);
    expect(bitString(decode(hex("03 01 00"))).length).toBe(0);
  });

  it("accepts zeroed unused bits in decode but not in bitString", () => {
    const e = decode(hex("03 02 01 fe"));
    expect(() => bitString(e)).toThrow(/unused bits/);
  });

  it("rejects set unused bits, counts over 7 and a missing count octet", () => {
    expect(() => decode(hex("03 02 01 ff"))).toThrow(/unused bits must be zero/);
    expect(() => decode(hex("03 02 08 00"))).toThrow(/exceeds 7/);
    expect(() => decode(hex("03 01 01"))).toThrow(/empty BIT STRING/);
    expect(() => decode(hex("03 00"))).toThrow(/unused-bits octet/);
  });
});

describe("der NULL and OBJECT IDENTIFIER", () => {
  it("requires NULL to be empty", () => {
    expect(decode(hex("05 00")).value.length).toBe(0);
    expect(() => decode(hex("05 01 00"))).toThrow(/NULL/);
  });

  it("decodes dotted OIDs including multi-byte arcs and the 2.x branch", () => {
    expect(oid(decode(hex("06 03 2a 03 04")))).toBe("1.2.3.4");
    expect(oid(decode(hex("06 06 2a 86 48 86 f7 0d")))).toBe("1.2.840.113549");
    expect(oid(decode(hex("06 03 55 04 03")))).toBe("2.5.4.3");
    expect(oid(decode(hex("06 09 60 86 48 01 65 03 04 02 02")))).toBe("2.16.840.1.101.3.4.2.2");
  });

  it("rejects empty, truncated and non-minimal sub-identifiers", () => {
    expect(() => decode(hex("06 00"))).toThrow(/no content/);
    expect(() => decode(hex("06 02 2a 81"))).toThrow(/truncated/);
    expect(() => decode(hex("06 03 2a 80 01"))).toThrow(/minimally/);
    expect(() => oid(decode(hex("02 01 01")))).toThrow(/expected OBJECT IDENTIFIER/);
  });
});

describe("der time", () => {
  it("decodes UTCTime with the two-digit year pivot at 50", () => {
    expect(time(decode(utcTime("241231235959Z"))).toISOString()).toBe("2024-12-31T23:59:59.000Z");
    expect(time(decode(utcTime("500101000000Z"))).getUTCFullYear()).toBe(1950);
    expect(time(decode(utcTime("490101000000Z"))).getUTCFullYear()).toBe(2049);
  });

  it("decodes GeneralizedTime", () => {
    expect(time(decode(tlv(0x18, ascii("20491231235959Z")))).toISOString()).toBe("2049-12-31T23:59:59.000Z");
  });

  it("rejects a missing 'Z', offsets, fractional seconds and short forms", () => {
    expect(() => decode(utcTime("241231235959"))).toThrow(/'Z'/);
    expect(() => decode(utcTime("241231235959+0000"))).toThrow(/'Z'/);
    expect(() => decode(utcTime("241231235959.000Z"))).toThrow(/'Z'/);
    expect(() => decode(utcTime("2412312359Z"))).toThrow(/'Z'/);
    expect(() => decode(tlv(0x18, ascii("20241231235959.5Z")))).toThrow(/'Z'/);
    expect(() => decode(tlv(0x18, ascii("241231235959Z")))).toThrow(/'Z'/);
  });

  it("rejects impossible calendar dates", () => {
    expect(() => decode(utcTime("241331000000Z"))).toThrow(/calendar/);
    expect(() => decode(utcTime("240230000000Z"))).toThrow(/calendar/);
    expect(() => decode(utcTime("241231240000Z"))).toThrow(/calendar/);
    expect(() => decode(utcTime("241231235960Z"))).toThrow(/calendar/);
  });

  it("rejects non-time tags", () => {
    expect(() => time(decode(hex("02 01 01")))).toThrow(/expected UTCTime/);
  });
});

// ---------------------------------------------------------------- pemBlocks

describe("der.pemBlocks", () => {
  it("returns the DER of each block with the label, in order", () => {
    const blocks = pemBlocks(AMD_GENOA_CERT_CHAIN_PEM, "CERTIFICATE");
    expect(blocks.length).toBe(2);
    expect(blocks[0][0]).toBe(0x30);
    expect(pemBlocks(AMD_GENOA_CERT_CHAIN_PEM, "X509 CRL")).toEqual([]);
  });

  it("skips blocks of other labels and tolerates CRLF line endings", () => {
    const mixed = "-----BEGIN PRIVATE KEY-----\r\nAAAA\r\n-----END PRIVATE KEY-----\r\n" + AMD_GENOA_CERT_CHAIN_PEM.replace(/\n/g, "\r\n");
    expect(pemBlocks(mixed, "CERTIFICATE").length).toBe(2);
  });

  it("rejects unterminated, empty and malformed blocks", () => {
    expect(() => pemBlocks("-----BEGIN CERTIFICATE-----\nAAAA\n", "CERTIFICATE")).toThrow(/unterminated/);
    expect(() => pemBlocks("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n", "CERTIFICATE")).toThrow(/empty/);
    expect(() => pemBlocks("-----BEGIN CERTIFICATE-----\nAAA*\n-----END CERTIFICATE-----\n", "CERTIFICATE")).toThrow(/base64/);
    expect(() => pemBlocks("-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n", "CERTIFICATE")).toThrow(/multiple of 4/);
    expect(() => pemBlocks("-----BEGIN CERTIFICATE-----\nA=AA\n-----END CERTIFICATE-----\n", "CERTIFICATE")).toThrow(/padding/);
    expect(() =>
      pemBlocks("-----BEGIN CERTIFICATE-----\nAAAA\n-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n", "CERTIFICATE"),
    ).toThrow(/boundary/);
  });

  it("decodes padded bodies exactly", () => {
    expect(Array.from(pemBlocks("-----BEGIN X-----\nAQ==\n-----END X-----", "X")[0])).toEqual([1]);
    expect(Array.from(pemBlocks("-----BEGIN X-----\nAQI=\n-----END X-----", "X")[0])).toEqual([1, 2]);
    expect(Array.from(pemBlocks("-----BEGIN X-----\nAQID\n-----END X-----", "X")[0])).toEqual([1, 2, 3]);
  });
});

// ---------------------------------------------------------------- ecdsaSignatureToRaw

describe("der.ecdsaSignatureToRaw", () => {
  it("right-aligns small r and s into fixed-width halves", () => {
    const raw = ecdsaSignatureToRaw(seq(int(1), int(2)), 32);
    expect(raw.length).toBe(64);
    expect(raw[31]).toBe(1);
    expect(raw[63]).toBe(2);
    expect(raw.filter((b) => b !== 0).length).toBe(2);
  });

  it("strips the sign byte of a full-width component", () => {
    const r = new Uint8Array(32).fill(0x80);
    const s = new Uint8Array(32).fill(0x7f);
    const raw = ecdsaSignatureToRaw(seq(int(0, ...r), int(...s)), 32);
    expect(raw.subarray(0, 32)).toEqual(r);
    expect(raw.subarray(32)).toEqual(s);
  });

  it("round-trips a real P-256 signature", () => {
    const raw = ecdsaSignatureToRaw(intelRoot.signature, 32);
    expect(raw.length).toBe(64);
    const r = BigInt("0x" + Buffer.from(raw.subarray(0, 32)).toString("hex"));
    const [rEl] = children(decode(intelRoot.signature));
    expect(integer(rEl)).toBe(r);
  });

  it("rejects non-minimal, negative, zero, oversized and malformed signatures", () => {
    expect(() => ecdsaSignatureToRaw(seq(int(0, 1), int(2)), 32)).toThrow(/minimally/);
    expect(() => ecdsaSignatureToRaw(seq(int(0x80), int(2)), 32)).toThrow(/negative/);
    expect(() => ecdsaSignatureToRaw(seq(int(0), int(2)), 32)).toThrow(/zero/);
    const big = new Uint8Array(33).fill(0x01);
    expect(() => ecdsaSignatureToRaw(seq(int(...big), int(2)), 32)).toThrow(/exceeds/);
    expect(() => ecdsaSignatureToRaw(seq(int(1)), 32)).toThrow(/exactly r and s/);
    expect(() => ecdsaSignatureToRaw(seq(int(1), int(2), int(3)), 32)).toThrow(/exactly r and s/);
    expect(() => ecdsaSignatureToRaw(new Uint8Array([...seq(int(1), int(2)), 0]), 32)).toThrow(/trailing/);
    expect(() => ecdsaSignatureToRaw(int(1), 32)).toThrow(/SEQUENCE/);
    expect(() => ecdsaSignatureToRaw(seq(int(1), tlv(0x04, [2])), 32)).toThrow(/expected INTEGER/);
  });
});

// ---------------------------------------------------------------- parseCertificate

describe("parseCertificate", () => {
  it("reads the embedded AMD Genoa ASK and ARK", () => {
    expect(genoaAsk.subjectCommonName).toBe("SEV-Genoa");
    expect(genoaArk.subjectCommonName).toBe("ARK-Genoa");
    expect(genoaAsk.signatureAlgorithm).toBe("rsa-pss-sha384");
    expect(genoaAsk.serialNumber).toBe(0x020002n);
    expect(genoaArk.serialNumber).toBe(0x020000n);
    expect(genoaAsk.issuer).toEqual(genoaArk.subject);
    expect(genoaArk.issuer).toEqual(genoaArk.subject);
    expect(genoaAsk.notBefore.toISOString()).toBe("2022-10-31T13:33:48.000Z");
    expect(genoaAsk.notAfter.toISOString()).toBe("2047-10-31T13:33:48.000Z");
    expect(genoaAsk.signature.length).toBe(512);
    expect(genoaAsk.spki[0]).toBe(0x30);
    expect(genoaAsk.tbs[0]).toBe(0x30);
    expect(genoaAsk.raw.length).toBeGreaterThan(genoaAsk.tbs.length + genoaAsk.signature.length);
  });

  it("reads the embedded AMD Turin chain and the Intel root", () => {
    expect(turinAsk.subjectCommonName).toBe("SEV-Turin");
    expect(turinArk.subjectCommonName).toBe("ARK-Turin");
    expect(intelRoot.subjectCommonName).toBe("Intel SGX Root CA");
    expect(intelRoot.signatureAlgorithm).toBe("ecdsa-p256-sha256");
    expect(intelRoot.issuer).toEqual(intelRoot.subject);
    expect(intelRoot.notAfter.toISOString()).toBe("2049-12-31T23:59:59.000Z");
  });

  it("exposes extensions with their critical flag", () => {
    const bc = extension(genoaAsk, "2.5.29.19");
    expect(bc?.critical).toBe(true);
    expect(basicConstraints(genoaAsk)).toEqual({ ca: true, pathLength: 0n });
    expect(basicConstraints(genoaArk)).toEqual({ ca: true });
    expect(basicConstraints(intelRoot)).toEqual({ ca: true, pathLength: 1n });
    expect(extension(genoaAsk, "2.5.29.99")).toBeUndefined();
    const crlDp = extension(genoaAsk, "2.5.29.31");
    expect(crlDp?.critical).toBe(false);
    expect(new TextDecoder().decode(crlDp?.value)).toContain("https://kdsintf.amd.com/vcek/v1/Genoa/crl");
  });

  describe.skipIf(withoutVectors)(vectorsTitle("production VCEK"), () => {
    beforeAll(loadMaterial);

    it("reads a production VCEK with its AMD extensions", () => {
      const [vcek] = amdChain(amdReal);
      expect(vcek.subjectCommonName).toBe("SEV-VCEK");
      expect(vcek.signatureAlgorithm).toBe("rsa-pss-sha384");
      expect(extension(vcek, "1.3.6.1.4.1.3704.1.4")?.value.length).toBe(64);
      expect(basicConstraints(vcek)).toBeUndefined();
    });
  });

  it("reads an RSA PKCS#1 v1.5 SHA-256 certificate", () => {
    const [cert] = certs(rsaPkcs1Pem);
    expect(cert.signatureAlgorithm).toBe("rsa-pkcs1-sha256");
    expect(cert.subjectCommonName).toBe("rsa-pkcs1 test");
    expect(cert.serialNumber).toBe(1n);
  });

  it("rejects trailing bytes, truncation and non-certificates", () => {
    const raw = genoaArk.raw;
    expect(() => parseCertificate(new Uint8Array([...raw, 0]))).toThrow(X509Error);
    expect(() => parseCertificate(raw.subarray(0, raw.length - 1))).toThrow(X509Error);
    expect(() => parseCertificate(int(1))).toThrow(/SEQUENCE/);
    expect(() => parseCertificate(seq(int(1), int(2)))).toThrow(/tbsCertificate/);
  });

  it("rejects an unsupported signature algorithm", () => {
    // ecdsa-with-SHA256 → ecdsa-with-SHA512 in both the inner and outer identifiers.
    const raw = new Uint8Array(intelRoot.raw);
    const pattern = hex("06 08 2a 86 48 ce 3d 04 03 02");
    let hits = 0;
    for (let i = 0; i + pattern.length <= raw.length; i++) {
      if (pattern.every((b, j) => raw[i + j] === b)) {
        raw[i + pattern.length - 1] = 0x04;
        hits++;
      }
    }
    expect(hits).toBe(2);
    expect(() => parseCertificate(raw)).toThrow(/unsupported signature algorithm/);
  });

  it("rejects differing inner and outer signature algorithms", () => {
    const raw = new Uint8Array(intelRoot.raw);
    const pattern = hex("06 08 2a 86 48 ce 3d 04 03 02");
    for (let i = 0; i + pattern.length <= raw.length; i++) {
      if (pattern.every((b, j) => raw[i + j] === b)) {
        raw[i + pattern.length - 1] = 0x03;
        break;
      }
    }
    expect(() => parseCertificate(raw)).toThrow(/inner and outer/);
  });

  it("rejects RSA-PSS parameters other than SHA-384 with a 48-byte salt", () => {
    // The salt length INTEGER 48 (0x30) inside [2] of the PSS parameters, in both identifiers.
    const raw = new Uint8Array(genoaArk.raw);
    const pattern = hex("a2 03 02 01 30");
    let hits = 0;
    for (let i = 0; i + pattern.length <= raw.length; i++) {
      if (pattern.every((b, j) => raw[i + j] === b)) {
        raw[i + pattern.length - 1] = 0x20;
        hits++;
      }
    }
    expect(hits).toBe(2);
    expect(() => parseCertificate(raw)).toThrow(/48-byte salt/);
  });
});

// ---------------------------------------------------------------- verifyCertificateSignature

describe("verifyCertificateSignature", () => {
  describe.skipIf(withoutVectors)(vectorsTitle("conformance chains"), () => {
    beforeAll(loadMaterial);

    it("verifies RSA-PSS SHA-384 signatures in the AMD chains", async () => {
      await expect(verifyCertificateSignature(genoaArk, genoaArk.spki)).resolves.toBe(true);
      await expect(verifyCertificateSignature(genoaAsk, genoaArk.spki)).resolves.toBe(true);
      await expect(verifyCertificateSignature(turinAsk, turinArk.spki)).resolves.toBe(true);
      const [vcek, ask] = amdChain(amdReal);
      await expect(verifyCertificateSignature(vcek, ask.spki)).resolves.toBe(true);
    });

    it("verifies ECDSA P-256 signatures", async () => {
      await expect(verifyCertificateSignature(intelRoot, intelRoot.spki)).resolves.toBe(true);
      const [pck, platformCa, root] = certs(intelSynthetic["tdx-happy"].pck_chain_pem);
      await expect(verifyCertificateSignature(pck, platformCa.spki)).resolves.toBe(true);
      await expect(verifyCertificateSignature(platformCa, root.spki)).resolves.toBe(true);
    });
  });

  it("verifies RSA PKCS#1 v1.5 SHA-256 signatures", async () => {
    const [cert] = certs(rsaPkcs1Pem);
    await expect(verifyCertificateSignature(cert, cert.spki)).resolves.toBe(true);
    await expect(verifyCertificateSignature(cert, genoaArk.spki)).resolves.toBe(false);
  });

  it("rejects the wrong key, a wrong key type and a tampered certificate", async () => {
    await expect(verifyCertificateSignature(genoaAsk, genoaAsk.spki)).resolves.toBe(false);
    await expect(verifyCertificateSignature(genoaAsk, turinArk.spki)).resolves.toBe(false);
    await expect(verifyCertificateSignature(genoaAsk, intelRoot.spki)).resolves.toBe(false);
    await expect(verifyCertificateSignature(intelRoot, genoaArk.spki)).resolves.toBe(false);
    // Flipping the last key byte changes the signed bytes without breaking the structure.
    await expect(verifyCertificateSignature(tamper(genoaAsk, genoaAsk.spki, genoaAsk.spki.length - 1), genoaArk.spki)).resolves.toBe(
      false,
    );
    await expect(verifyCertificateSignature(tamper(genoaAsk, genoaAsk.signature, 3), genoaArk.spki)).resolves.toBe(false);
    await expect(verifyCertificateSignature(tamper(intelRoot, intelRoot.spki, intelRoot.spki.length - 1), intelRoot.spki)).resolves.toBe(
      false,
    );
  });

  it("rejects a malformed issuer key instead of throwing", async () => {
    await expect(verifyCertificateSignature(genoaAsk, int(1))).resolves.toBe(false);
    await expect(verifyCertificateSignature(genoaAsk, genoaArk.spki.subarray(0, 50))).resolves.toBe(false);
  });

  it("accepts an RSA key labelled id-RSASSA-PSS", async () => {
    const spki = new Uint8Array(genoaArk.spki);
    const pattern = hex("06 09 2a 86 48 86 f7 0d 01 01 01");
    const at = spki.findIndex((_, i) => pattern.every((b, j) => spki[i + j] === b));
    expect(at).toBeGreaterThan(0);
    spki[at + pattern.length - 1] = 0x0a;
    await expect(verifyCertificateSignature(genoaAsk, spki)).resolves.toBe(true);
  });

  it("rejects an ECDSA signature whose DER is not minimal", async () => {
    // Re-encode r with a redundant leading zero; the value is unchanged.
    const [r, s] = children(decode(intelRoot.signature));
    const padded = seq(int(0, ...r.value), s.raw);
    const raw = new Uint8Array(intelRoot.raw);
    const sigAt = intelRoot.signature.byteOffset - intelRoot.raw.byteOffset;
    const rebuilt = new Uint8Array([...raw.subarray(0, sigAt), ...padded]);
    const cert: Certificate = { ...intelRoot, raw: rebuilt, signature: padded };
    await expect(verifyCertificateSignature(cert, intelRoot.spki)).resolves.toBe(false);
  });
});

// ---------------------------------------------------------------- verifyChain

describe.skipIf(withoutVectors)(vectorsTitle("verifyChain"), () => {
  let realAt: Date;
  beforeAll(() => {
    loadMaterial();
    realAt = unix(amdReal.verification_time_unix);
  });

  it("accepts the production VCEK → ASK → ARK chain at the capture time", async () => {
    const chain = amdChain(amdReal);
    expect(chain.map((c) => c.subjectCommonName)).toEqual(["SEV-VCEK", "SEV-Genoa", "ARK-Genoa"]);
    await expect(verifyChain(chain, [genoaArk], realAt)).resolves.toBeUndefined();
    await expect(verifyChain(chain, [turinArk, genoaArk], realAt)).resolves.toBeUndefined();
  });

  it("accepts the embedded ASK → ARK chains and the Intel root alone", async () => {
    await expect(verifyChain([genoaAsk, genoaArk], [genoaArk], realAt)).resolves.toBeUndefined();
    await expect(verifyChain([turinAsk, turinArk], [turinArk], realAt)).resolves.toBeUndefined();
    await expect(verifyChain([intelRoot], [intelRoot], realAt)).resolves.toBeUndefined();
  });

  it("accepts a synthetic PCK chain against its own root", async () => {
    const set = intelSynthetic["tdx-happy"];
    const chain = certs(set.pck_chain_pem);
    const [root] = certs(set.root_pem);
    await expect(verifyChain(chain, [root], new Date("2025-06-01T00:00:00Z"))).resolves.toBeUndefined();
  });

  it("rejects a chain that does not end in one of the roots", async () => {
    const chain = amdChain(amdReal);
    await expect(verifyChain(chain, [turinArk], realAt)).rejects.toThrow(/trusted root/);
    await expect(verifyChain(chain, [], realAt)).rejects.toThrow(/trusted root/);
    await expect(verifyChain(chain.slice(0, 2), [genoaArk], realAt)).rejects.toThrow(/trusted root/);
    const tdx = intelSynthetic["t25-wrong-root"];
    await expect(verifyChain(certs(tdx.pck_chain_pem), [intelRoot], new Date("2025-06-01T00:00:00Z"))).rejects.toThrow(
      /trusted root/,
    );
    const sev = amdSynthetic["s26-wrong-root"];
    await expect(verifyChain(amdChain(sev), certs(sev.root_pem!), new Date("2025-06-01T00:00:00Z"))).rejects.toThrow(X509Error);
  });

  it("rejects a certificate that is not valid at the verification time", async () => {
    const chain = amdChain(amdReal);
    await expect(verifyChain(chain, [genoaArk], new Date("2000-01-01T00:00:00Z"))).rejects.toThrow(/not valid at/);
    await expect(verifyChain(chain, [genoaArk], new Date("2100-01-01T00:00:00Z"))).rejects.toThrow(/not valid at/);
    await expect(verifyChain(chain, [genoaArk], new Date(NaN))).rejects.toThrow(/invalid/);
    // The validity window is inclusive at both ends. The ASK starts after and
    // the ARK ends before the other, so each bounds the chain on one side.
    await expect(verifyChain([genoaAsk, genoaArk], [genoaArk], genoaAsk.notBefore)).resolves.toBeUndefined();
    await expect(verifyChain([genoaAsk, genoaArk], [genoaArk], new Date(genoaAsk.notBefore.getTime() - 1))).rejects.toThrow(
      /certificate 0 .* not valid at/,
    );
    await expect(verifyChain([genoaAsk, genoaArk], [genoaArk], genoaArk.notAfter)).resolves.toBeUndefined();
    await expect(verifyChain([genoaAsk, genoaArk], [genoaArk], new Date(genoaArk.notAfter.getTime() + 1))).rejects.toThrow(
      /certificate 1 .* not valid at/,
    );
  });

  it("rejects an issuer that is not a certificate authority", async () => {
    const [vcek, , ark] = amdChain(amdReal);
    await expect(verifyChain([vcek, vcek, ark], [ark], realAt)).rejects.toThrow(/not a certificate authority/);
    const [pck, platformCa, root] = certs(intelSynthetic["tdx-happy"].pck_chain_pem);
    await expect(verifyChain([pck, pck, platformCa, root], [root], new Date("2025-06-01T00:00:00Z"))).rejects.toThrow(
      /not a certificate authority/,
    );
  });

  it("rejects an issuer whose path length constraint is exceeded", async () => {
    const [vcek, ask, ark] = amdChain(amdReal);
    await expect(verifyChain([vcek, ask, ask, ark], [ark], realAt)).rejects.toThrow(/path length/);
  });

  it("rejects issuer and subject names that differ", async () => {
    const [vcek, , ark] = amdChain(amdReal);
    await expect(verifyChain([vcek, ark], [ark], realAt)).rejects.toThrow(/issuer does not match/);
    await expect(verifyChain([genoaAsk, turinArk], [turinArk], realAt)).rejects.toThrow(/issuer does not match/);
  });

  it("rejects a tampered signature or a tampered signed body", async () => {
    const [vcek, ask, ark] = amdChain(amdReal);
    await expect(verifyChain([tamper(vcek, vcek.signature, 5), ask, ark], [ark], realAt)).rejects.toThrow(/signature does not verify/);
    const badAsk = tamper(ask, ask.signature, 5);
    await expect(verifyChain([vcek, badAsk, ark], [ark], realAt)).rejects.toThrow(/signature does not verify/);
    // A change to the leaf's signed bytes other than its names still fails the signature.
    const spkiAt = vcek.spki.byteOffset - vcek.raw.byteOffset;
    const bodyTampered = tamper(vcek, vcek.raw, spkiAt + vcek.spki.length - 1);
    await expect(verifyChain([bodyTampered, ask, ark], [ark], realAt)).rejects.toThrow(/signature does not verify/);
  });

  it("rejects the conformance chain that is structurally broken", async () => {
    const set = amdSynthetic["struct-bad-chain"];
    const run = async (): Promise<void> => verifyChain(amdChain(set), certs(set.root_pem!), new Date("2025-06-01T00:00:00Z"));
    await expect(run()).rejects.toThrow(X509Error);
  });

  it("accepts the synthetic conformance chain at a time inside every window", async () => {
    const set = amdSynthetic["sev-happy"];
    await expect(verifyChain(amdChain(set), certs(set.root_pem!), new Date("2025-06-01T00:00:00Z"))).resolves.toBeUndefined();
  });

  it("rejects an empty chain", async () => {
    await expect(verifyChain([], [genoaArk], realAt)).rejects.toThrow(/empty/);
  });
});

// ---------------------------------------------------------------- spkiFingerprint

describe("spkiFingerprint", () => {
  it("is the lowercase hex SHA-256 of the DER SubjectPublicKeyInfo", async () => {
    const expected = createHash("sha256").update(genoaArk.spki).digest("hex");
    await expect(spkiFingerprint(genoaArk.spki)).resolves.toBe(expected);
    expect(expected).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ---------------------------------------------------------------- revocation lists

describe("parseRevocationList", () => {
  describe.skipIf(withoutVectors)(vectorsTitle("conformance CRLs"), () => {
    let crl: ReturnType<typeof parseRevocationList>;
    beforeAll(() => {
      loadMaterial();
      crl = parseRevocationList(b64(amdReal.crl_der_base64));
    });

    it("reads the production AMD CRL", () => {
      expect(crl.issuer).toEqual(genoaArk.subject);
      expect(crl.signatureAlgorithm).toBe("rsa-pss-sha384");
      expect(crl.signature.length).toBe(512);
      expect(crl.thisUpdate.toISOString()).toBe("2026-07-28T04:07:23.000Z");
      expect(crl.nextUpdate.toISOString()).toBe("2026-09-09T00:00:00.000Z");
      expect(crl.revokedSerials).toEqual([0x020001n]);
      expect(crl.tbs[0]).toBe(0x30);
      expect(crl.raw.length).toBeGreaterThan(crl.tbs.length);
    });

    it("reads ECDSA CRLs from the Intel collateral", () => {
      const set = intelSynthetic["tdx-happy"];
      const pckCrl = parseRevocationList(b64(set.pck_crl_der_base64));
      const [platformCa] = certs(set.pck_crl_issuer_chain_pem);
      expect(pckCrl.signatureAlgorithm).toBe("ecdsa-p256-sha256");
      expect(pckCrl.issuer).toEqual(platformCa.subject);
      expect(pckCrl.revokedSerials).toEqual([]);
      const rootCrl = parseRevocationList(b64(set.root_crl_der_base64));
      expect(rootCrl.issuer).toEqual(certs(set.root_pem)[0].subject);
    });

    it("rejects trailing bytes, truncation and non-CRLs", () => {
      const raw = crl.raw;
      expect(() => parseRevocationList(new Uint8Array([...raw, 0]))).toThrow(X509Error);
      expect(() => parseRevocationList(raw.subarray(0, raw.length - 1))).toThrow(X509Error);
      expect(() => parseRevocationList(genoaArk.raw)).toThrow(X509Error);
      expect(() => parseRevocationList(int(1))).toThrow(/SEQUENCE/);
    });
  });

  it("rejects a CRL without nextUpdate", () => {
    const alg = seq(tlv(0x06, hex("2a 86 48 ce 3d 04 03 02")));
    const issuer = seq();
    const build = (...after: Uint8Array[]): Uint8Array =>
      seq(seq(int(1), alg, issuer, utcTime("240101000000Z"), ...after), alg, tlv(0x03, [0, ...seq(int(1), int(1))]));
    expect(() => parseRevocationList(build())).toThrow(/nextUpdate is required/);
    expect(() => parseRevocationList(build(seq()))).toThrow(/nextUpdate is required/);
    const ok = parseRevocationList(build(utcTime("250101000000Z"), seq(seq(int(7), utcTime("240601000000Z")))));
    expect(ok.revokedSerials).toEqual([7n]);
    expect(ok.nextUpdate.toISOString()).toBe("2025-01-01T00:00:00.000Z");
    expect(() => parseRevocationList(build(utcTime("230101000000Z")))).toThrow(/after nextUpdate/);
    expect(() => parseRevocationList(build(utcTime("250101000000Z"), int(1)))).toThrow(/unexpected field/);
  });
});

describe.skipIf(withoutVectors)(vectorsTitle("verifyRevocationList"), () => {
  let crl: ReturnType<typeof parseRevocationList>;
  let realAt: Date;
  beforeAll(() => {
    loadMaterial();
    crl = parseRevocationList(b64(amdReal.crl_der_base64));
    realAt = unix(amdReal.verification_time_unix);
  });

  it("accepts the production CRL under the ARK inside its window", async () => {
    await expect(verifyRevocationList(crl, genoaArk, realAt)).resolves.toBeUndefined();
    await expect(verifyRevocationList(crl, genoaArk, crl.thisUpdate)).resolves.toBeUndefined();
    await expect(verifyRevocationList(crl, genoaArk, crl.nextUpdate)).resolves.toBeUndefined();
  });

  it("rejects a time outside [thisUpdate, nextUpdate]", async () => {
    await expect(verifyRevocationList(crl, genoaArk, new Date(crl.thisUpdate.getTime() - 1))).rejects.toThrow(/not current/);
    await expect(verifyRevocationList(crl, genoaArk, new Date(crl.nextUpdate.getTime() + 1))).rejects.toThrow(/not current/);
    await expect(verifyRevocationList(crl, genoaArk, new Date(NaN))).rejects.toThrow(/invalid/);
  });

  it("rejects an issuer whose name or key does not match", async () => {
    await expect(verifyRevocationList(crl, genoaAsk, realAt)).rejects.toThrow(/issuer does not match/);
    await expect(verifyRevocationList(crl, turinArk, realAt)).rejects.toThrow(/issuer does not match/);
    const impostor: Certificate = { ...turinArk, subject: genoaArk.subject };
    await expect(verifyRevocationList(crl, impostor, realAt)).rejects.toThrow(/signature does not verify/);
  });

  it("rejects a tampered signature or body", async () => {
    const sig = new Uint8Array(crl.signature);
    sig[0] ^= 1;
    await expect(verifyRevocationList({ ...crl, signature: sig }, genoaArk, realAt)).rejects.toThrow(/signature does not verify/);
    const tbs = new Uint8Array(crl.tbs);
    tbs[tbs.length - 1] ^= 1;
    await expect(verifyRevocationList({ ...crl, tbs }, genoaArk, realAt)).rejects.toThrow(/signature does not verify/);
  });

  it("rejects an issuer that may not sign revocation lists", async () => {
    const [vcek] = amdChain(amdReal);
    const leaf: Certificate = { ...vcek, subject: genoaArk.subject };
    await expect(verifyRevocationList(crl, leaf, realAt)).rejects.toThrow(/may not sign/);
  });

  it("verifies the Intel PCK and root CRLs under their issuers", async () => {
    const set = intelSynthetic["tdx-happy"];
    const [platformCa] = certs(set.pck_crl_issuer_chain_pem);
    const [root] = certs(set.root_pem);
    const at = new Date("2025-06-01T00:00:00Z");
    await expect(verifyRevocationList(parseRevocationList(b64(set.pck_crl_der_base64)), platformCa, at)).resolves.toBeUndefined();
    await expect(verifyRevocationList(parseRevocationList(b64(set.root_crl_der_base64)), root, at)).resolves.toBeUndefined();
    await expect(verifyRevocationList(parseRevocationList(b64(set.pck_crl_der_base64)), root, at)).rejects.toThrow(
      /issuer does not match/,
    );
  });

  it("matches the conformance CRL-window verdicts for AMD", async () => {
    const at = (set: AmdMaterial): Date => (set.verification_time_unix !== undefined ? unix(set.verification_time_unix) : new Date());
    const run = (set: AmdMaterial): Promise<void> => {
      const [, , ark] = amdChain(set);
      return verifyRevocationList(parseRevocationList(b64(set.crl_der_base64)), ark, at(set));
    };
    await expect(run(amdSynthetic["struct-crl-expired"])).rejects.toThrow(/not current/);
    await expect(run(amdSynthetic["struct-crl-not-yet-valid"])).rejects.toThrow(/not current/);
    await expect(run(amdSynthetic["struct-crl-at-this-update"])).resolves.toBeUndefined();
    const atThis = amdSynthetic["struct-crl-at-this-update"];
    expect(parseRevocationList(b64(atThis.crl_der_base64)).thisUpdate).toEqual(unix(atThis.verification_time_unix!));
  });

  it("matches the conformance CRL-window verdicts for Intel", async () => {
    const at = (set: IntelMaterial): Date => (set.verification_time_unix !== undefined ? unix(set.verification_time_unix) : new Date());
    const run = (set: IntelMaterial): Promise<void> => {
      const [platformCa] = certs(set.pck_crl_issuer_chain_pem);
      return verifyRevocationList(parseRevocationList(b64(set.pck_crl_der_base64)), platformCa, at(set));
    };
    await expect(run(intelSynthetic["t24-crl-expired"])).rejects.toThrow(/not current/);
    await expect(run(intelSynthetic["t24-crl-not-yet-valid"])).rejects.toThrow(/not current/);
    await expect(run(intelSynthetic["t24-crl-at-this-update"])).resolves.toBeUndefined();
  });
});

describe.skipIf(withoutVectors)(vectorsTitle("isRevoked"), () => {
  beforeAll(loadMaterial);

  it("matches serials exactly", () => {
    const crl = parseRevocationList(b64(amdReal.crl_der_base64));
    expect(isRevoked(crl, 0x020001n)).toBe(true);
    expect(isRevoked(crl, genoaAsk.serialNumber)).toBe(false);
    expect(isRevoked(crl, 0x02000100n)).toBe(false);
    expect(isRevoked(crl, 0n)).toBe(false);
  });

  it("finds the revoked ASK in the conformance set", async () => {
    const set = amdSynthetic["s26-revoked-ask"];
    const [, ask, ark] = amdChain(set);
    const crl = parseRevocationList(b64(set.crl_der_base64));
    await expect(verifyRevocationList(crl, ark, new Date("2025-06-01T00:00:00Z"))).resolves.toBeUndefined();
    expect(isRevoked(crl, ask.serialNumber)).toBe(true);
    const happy = parseRevocationList(b64(amdSynthetic["sev-happy"].crl_der_base64));
    expect(isRevoked(happy, ask.serialNumber)).toBe(false);
  });
});
