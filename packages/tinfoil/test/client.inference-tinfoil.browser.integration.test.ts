import { describe, it, expect } from "vitest";
import { TinfoilAI } from "../src/tinfoil-ai";
import { Client } from "../src/client";
import { TINFOIL_CONFIG } from "../src/config";

describe("TinfoilAI - enclaveURL integration", () => {
  const INFERENCE_URL = "https://inference.tinfoil.sh";

  it("should verify enclave when enclaveURL is set to inference.tinfoil.sh", async () => {
    const client = new TinfoilAI({
      bearerToken: process.env.TINFOIL_API_KEY,
      enclaveURL: INFERENCE_URL,
    });

    await client.ready();

    const verificationDoc = client.inspect()?.verification;

    expect(verificationDoc).toBeTruthy();
    expect(verificationDoc?.freshnessExpiresAt?.getTime()).toBeGreaterThan(Date.now());
    expect(verificationDoc?.tlsPublicKeyFingerprint()).toBeTruthy();
  }, 60000);

  it("should verify enclave when only baseURL is set to inference.tinfoil.sh", async () => {
    const client = new TinfoilAI({
      bearerToken: process.env.TINFOIL_API_KEY,
      baseURL: `${INFERENCE_URL}/v1/`,
    });

    await client.ready();

    const verificationDoc = client.inspect()?.verification;

    expect(verificationDoc).toBeTruthy();
    expect(verificationDoc?.freshnessExpiresAt?.getTime()).toBeGreaterThan(Date.now());
  }, 60000);
});

describe("Client - enclaveURL integration", () => {
  const INFERENCE_URL = "https://inference.tinfoil.sh";

  it("should verify enclave when enclaveURL is set to inference.tinfoil.sh", async () => {
    const client = new Client({
      enclaveURL: INFERENCE_URL,
    });

    await client.ready();

    const verificationDoc = client.inspect()?.verification;

    expect(verificationDoc).toBeTruthy();
    expect(verificationDoc?.freshnessExpiresAt?.getTime()).toBeGreaterThan(Date.now());
    expect(verificationDoc?.tlsPublicKeyFingerprint()).toBeTruthy();
  }, 60000);

  it("should verify enclave when baseURL is set to inference.tinfoil.sh", async () => {
    const client = new Client({
      baseURL: `${INFERENCE_URL}/v1/`,
    });

    await client.ready();

    const verificationDoc = client.inspect()?.verification;

    expect(verificationDoc).toBeTruthy();
    expect(verificationDoc?.freshnessExpiresAt?.getTime()).toBeGreaterThan(Date.now());
  }, 60000);

  it("should make successful fetch request when enclaveURL is set to inference.tinfoil.sh", async () => {
    const client = new Client({
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
