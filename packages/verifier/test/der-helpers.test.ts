/**
 * The hand-built DER of the test helpers, checked against the verifier's own
 * decoder: an OBJECT IDENTIFIER whose first sub-identifier needs more than
 * one byte, and a certificate validity that lies outside the years a UTCTime
 * can name.
 */
import { describe, expect, it } from "vitest";
import { parseCertificate } from "../src/internal/x509/certificate.js";
import { decode, oid as decodeOid } from "../src/internal/x509/der.js";
import { newTimestampAuthority, oid, validityTime } from "./helpers/tsa.js";

describe("the DER test helpers", () => {
  it("encode every OID sub-identifier in base 128, the combined first two arcs included", () => {
    expect(Array.from(oid("2.100.3"))).toEqual([0x06, 0x03, 0x81, 0x34, 0x03]);
    for (const dotted of ["2.100.3", "2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.9.16.1.4", "2.5.4.3"]) {
      expect(decodeOid(decode(oid(dotted)))).toBe(dotted);
    }
  });

  it("choose UTCTime for 1950 through 2049 and GeneralizedTime outside", () => {
    expect(validityTime(new Date("1950-01-01T00:00:00Z"))[0]).toBe(0x17);
    expect(validityTime(new Date("2049-12-31T23:59:59Z"))[0]).toBe(0x17);
    expect(validityTime(new Date("1949-12-31T23:59:59Z"))[0]).toBe(0x18);
    expect(validityTime(new Date("2050-01-01T00:00:00Z"))[0]).toBe(0x18);
  });

  it("issue an authority whose validity lies beyond 2049 with the dates that were asked for", async () => {
    const notBefore = new Date("2050-01-01T00:00:00Z");
    const notAfter = new Date("2060-01-01T00:00:00Z");
    const tsa = await newTimestampAuthority({ notBefore, notAfter });
    for (const der of tsa.chainDer) {
      const cert = parseCertificate(der);
      expect(cert.notBefore).toEqual(notBefore);
      expect(cert.notAfter).toEqual(notAfter);
    }
  });
});
