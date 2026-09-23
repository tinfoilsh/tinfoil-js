import { describe, it, expect } from "vitest";
import { TinfoilAI } from "../src/tinfoil-ai";
import { SecureClient } from "../src/secure-client";
import { TINFOIL_CONFIG } from "../src/config";

describe("TinfoilAI - enclaveURL integration", () => {
  const INFERENCE_URL = "https://inference.tinfoil.sh";

  it("should verify enclave when enclaveURL is set to inference.tinfoil.sh", async () => {
    const client = new TinfoilAI({
      bearerToken: process.env.TINFOIL_API_KEY,
      enclaveURL: INFERENCE_URL,
    });

    await client.ready();

    const verificationDoc = await client.getVerificationDocument();

    expect(verificationDoc).toBeTruthy();
    expect(verificationDoc.configRepo).toBe(TINFOIL_CONFIG.DEFAULT_ROUTER_REPO);
    expect(verificationDoc.securityVerified).toBe(true);
    expect(verificationDoc.enclaveHost).toBeTruthy();
    expect(verificationDoc.enclaveMeasurement.tlsPublicKeyFingerprint).toBeTruthy();
  }, 60000);

  it("should verify enclave when only baseURL is set to inference.tinfoil.sh", async () => {
    const client = new TinfoilAI({
      bearerToken: process.env.TINFOIL_API_KEY,
      baseURL: `${INFERENCE_URL}/v1/`,
    });

    await client.ready();

    const verificationDoc = await client.getVerificationDocument();

    expect(verificationDoc).toBeTruthy();
    expect(verificationDoc.configRepo).toBe(TINFOIL_CONFIG.DEFAULT_ROUTER_REPO);
    expect(verificationDoc.securityVerified).toBe(true);
    expect(verificationDoc.enclaveHost).toBeTruthy();
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
    expect(verificationDoc.configRepo).toBe(TINFOIL_CONFIG.DEFAULT_ROUTER_REPO);
    expect(verificationDoc.securityVerified).toBe(true);
    expect(verificationDoc.enclaveHost).toBeTruthy();
    expect(verificationDoc.enclaveMeasurement.tlsPublicKeyFingerprint).toBeTruthy();
  }, 60000);

  it("should verify enclave when baseURL is set to inference.tinfoil.sh", async () => {
    const client = new SecureClient({
      baseURL: `${INFERENCE_URL}/v1/`,
    });

    await client.ready();

    const verificationDoc = await client.getVerificationDocument();

    expect(verificationDoc).toBeTruthy();
    expect(verificationDoc.configRepo).toBe(TINFOIL_CONFIG.DEFAULT_ROUTER_REPO);
    expect(verificationDoc.securityVerified).toBe(true);
    expect(verificationDoc.enclaveHost).toBeTruthy();
  }, 60000);

  it("should carry the v3 facts in the verification document and bind the transport to them", async () => {
    const client = new SecureClient({
      enclaveURL: INFERENCE_URL,
    });

    await client.ready();

    const doc = client.getVerificationDocument();
    expect(doc.securityVerified).toBe(true);
    expect(doc.schemaVersion).toBe(1);
    expect(doc.releaseDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(doc.releaseTag).toBeTruthy();
    expect(doc.codeFingerprint).toBeTruthy();
    expect(doc.enclaveFingerprint).toBeTruthy();
    expect(doc.tlsPublicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(doc.hpkePublicKey).toBeTruthy();
    expect(doc.enclaveMeasurement.tlsPublicKeyFingerprint).toBe(doc.tlsPublicKey);
    expect(doc.enclaveMeasurement.hpkePublicKey).toBe(doc.hpkePublicKey);
    expect(doc.codeMeasurement.registers.length).toBeGreaterThan(0);
    expect(doc.enclaveMeasurement.measurement.registers.length).toBeGreaterThan(0);
    expect(doc.verifiedAt).toBeTruthy();
    expect(doc.steps).toMatchObject({
      fetchDigest: { status: "success" },
      verifyCode: { status: "success" },
      verifyEnclave: { status: "success" },
      compareMeasurements: { status: "success" },
    });

    // The EHBP transport is built from the same endorsed HPKE key the
    // document carries: a request round-trips only if the attested enclave
    // can decrypt it.
    const response = await client.fetch("/v1/models", { method: "GET" });
    expect(response.status).toBe(200);
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
