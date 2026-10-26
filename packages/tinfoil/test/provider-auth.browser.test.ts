import { describe, expect, it, vi } from "vitest";
const capture = vi.hoisted(() => ({ authorization: "" }));
vi.mock("../src/client.js", () => ({
  Client: class {
    getBaseURL() { return "https://enclave.test/v1/"; }
    async fetch(_input: RequestInfo | URL, init?: RequestInit) {
      capture.authorization = new Headers(init?.headers).get("authorization") ?? "";
      return Response.json({ data: [], object: "list" });
    }
    inspect() { return undefined; }
  },
  copyVerificationOptions: (value: unknown) => value,
}));
import { TinfoilAI, ConfigurationError, serializeSessionRecoveryToken } from "../src/index.browser.js";
describe("browser provider authentication", () => {
  it("uses the explicit bearer token and native resources through the secure request hook", async () => {
    const client = new TinfoilAI({ bearerToken: "synthetic-browser-token", apiKey: "superseded", maxRetries: 0 });
    await client.models.list(); expect(capture.authorization).toBe("Bearer synthetic-browser-token");
    expect(client.responses).toBeDefined(); expect(client.decisions).toBeDefined(); expect(typeof serializeSessionRecoveryToken).toBe("function");
  });
  it("requires explicit browser credentials without consulting environment secrets", () => {
    expect(() => new TinfoilAI()).toThrow(ConfigurationError);
  });
});
