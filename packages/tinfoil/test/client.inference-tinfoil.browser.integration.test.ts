import { describe, it, expect } from "vitest";
import { TinfoilAI } from "../src/tinfoil-ai";
import { SecureClient } from "../src/secure-client";
import { TINFOIL_CONFIG } from "../src/config";

describe("TinfoilAI - enclaveURL integration", () => {
  const INFERENCE_URL = "https://inference.tinfoil.sh";

  it("should verify enclave when enclaveURL is set to inference.tinfoil.sh", async () => {
    const client = new TinfoilAI({
      bearerToken: "tinfoil",
      enclaveURL: INFERENCE_URL,
    });

    await client.ready();

    const verificationDoc = await client.getVerificationDocument();

    expect(verificationDoc).toBeTruthy();
    expect(verificationDoc.configRepo).toBe(TINFOIL_CONFIG.INFERENCE_PROXY_REPO);
    expect(verificationDoc.securityVerified).toBe(true);
    expect(verificationDoc.enclaveHost).toBe("inference.tinfoil.sh");
    expect(verificationDoc.enclaveMeasurement.tlsPublicKeyFingerprint).toBeTruthy();
  }, 60000);

  it("should verify enclave when only baseURL is set to inference.tinfoil.sh", async () => {
    const client = new TinfoilAI({
      bearerToken: "tinfoil",
      baseURL: `${INFERENCE_URL}/v1/`,
    });

    await client.ready();

    const verificationDoc = await client.getVerificationDocument();

    expect(verificationDoc).toBeTruthy();
    expect(verificationDoc.configRepo).toBe(TINFOIL_CONFIG.INFERENCE_PROXY_REPO);
    expect(verificationDoc.securityVerified).toBe(true);
    expect(verificationDoc.enclaveHost).toBe("inference.tinfoil.sh");
  }, 60000);
});

describe("SecureClient - enclaveURL integration", () => {
  const INFERENCE_URL = "https://inference.tinfoil.sh";

  it("should verify enclave when enclaveURL is set to inference.tinfoil.sh", async () => {
    const client = new SecureClient({
      enclaveURL: INFERENCE_URL,
    });

    await client.ready();

    const verificationDoc = await client.getVerificationDocument();

    expect(verificationDoc).toBeTruthy();
    expect(verificationDoc.configRepo).toBe(TINFOIL_CONFIG.INFERENCE_PROXY_REPO);
    expect(verificationDoc.securityVerified).toBe(true);
    expect(verificationDoc.enclaveHost).toBe("inference.tinfoil.sh");
    expect(verificationDoc.enclaveMeasurement.tlsPublicKeyFingerprint).toBeTruthy();
  }, 60000);

  it("should verify enclave when baseURL is set to inference.tinfoil.sh", async () => {
    const client = new SecureClient({
      baseURL: `${INFERENCE_URL}/v1/`,
    });

    await client.ready();

    const verificationDoc = await client.getVerificationDocument();

    expect(verificationDoc).toBeTruthy();
    expect(verificationDoc.configRepo).toBe(TINFOIL_CONFIG.INFERENCE_PROXY_REPO);
    expect(verificationDoc.securityVerified).toBe(true);
    expect(verificationDoc.enclaveHost).toBe("inference.tinfoil.sh");
  }, 60000);

  it("should make successful fetch request when enclaveURL is set to inference.tinfoil.sh", async () => {
    const client = new SecureClient({
      enclaveURL: INFERENCE_URL,
    });

    await client.ready();

    const response = await client.fetch("/v1/models", {
      method: "GET",
    });

    expect(response.status).toBe(200);
    const data = await response.json();
    expect(data).toBeTruthy();
  }, 60000);
});
