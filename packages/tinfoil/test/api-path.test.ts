/**
 * The API path rule: an RFC 3986 `path-absolute` of path characters and
 * well-formed percent escapes, with "." and ".." segments, an encoded slash
 * or backslash, a leading `//`, a query and a fragment refused.
 */
import { describe, expect, it } from "vitest";
import { ConfigurationError } from "../src/errors.js";
import { joinAPIPath, validateAPIPath } from "../src/internal/api-path.js";

const PATH_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@/";

describe("validateAPIPath", () => {
  it("accepts every RFC 3986 path character and any well-formed escape, UTF-8 or not", () => {
    for (const apiPath of [
      "/abcdefghijklmnopqrstuvwxyz/ABCDEFGHIJKLMNOPQRSTUVWXYZ/0123456789/",
      "/-._~/",
      "/!$&'()*+,;=/",
      "/:@/",
      "/v%31/",
      "/a%20b/",
      "/%c3%a9/",
      "/%ff/",
      "/%C0%AF/",
      "/%2e%2e%2e/",
      "/.well-known/",
      "/.../",
    ]) {
      expect(() => validateAPIPath(apiPath), apiPath).not.toThrow();
      expect(joinAPIPath("https://enclave.example/", apiPath)).toBe(`https://enclave.example${apiPath}`);
    }
  });

  it("accepts exactly the path characters among every character up to U+00FF", () => {
    for (let c = 0; c < 256; c++) {
      const apiPath = `/a${String.fromCharCode(c)}b/`;
      if (PATH_CHARS.includes(String.fromCharCode(c))) expect(() => validateAPIPath(apiPath), JSON.stringify(apiPath)).not.toThrow();
      else expect(() => validateAPIPath(apiPath), JSON.stringify(apiPath)).toThrow(ConfigurationError);
    }
  });

  it("accepts every escape from %00 to %FF, in either case, except an encoded slash or backslash", () => {
    for (let b = 0; b < 256; b++) {
      for (const hex of [b.toString(16).padStart(2, "0"), b.toString(16).padStart(2, "0").toUpperCase()]) {
        const apiPath = `/a%${hex}b/`;
        if (b === 0x2f || b === 0x5c) expect(() => validateAPIPath(apiPath), apiPath).toThrow(/encoded slash or backslash/);
        else expect(() => validateAPIPath(apiPath), apiPath).not.toThrow();
      }
    }
  });

  it("refuses a malformed escape, a dot segment, a leading //, a query, a fragment or a relative path", () => {
    for (const apiPath of [
      "/a%/", "/a%2/", "/a%zz/", "/a%g0/", "/%/",
      "/./", "/../", "/v1/./x", "/v1/../x", "/%2e/", "/%2E%2e/", "/.%2e/", "/%2e./",
      "/v1%2fx/", "/v1%2Fx/", "/v1%5cx/", "/v1%5Cx/",
      "//evil.example/v1/", "/v1?x=1", "/v1#f", "/v1?", "/v1#",
      "v1/", "", "https://evil.example/v1/",
    ]) {
      expect(() => validateAPIPath(apiPath), apiPath).toThrow(ConfigurationError);
    }
  });
});
