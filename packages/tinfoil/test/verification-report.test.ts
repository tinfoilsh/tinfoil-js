/**
 * The verification reports that the clients expose: `lastVerification()`,
 * the `onVerification` option, the reports that `ensureVerified` and
 * `reverify` return, and the verifier's report on a rejection, through the
 * conformance cases of the client specification. The gateway's per-replica
 * case is in the gateway transport's tests.
 */
import { describe, expect, it } from "vitest";
import { createEnclaveHTTPClient, type EnclaveClientSeams } from "../src/enclave-client.js";
import { AttestationError, ConfigurationError, findTinfoilError, NetworkError, type TinfoilError } from "../src/errors.js";
import { Enclave } from "../src/internal/enclave.js";
import { KeyedTransport, KeyRejectionError, PeerLacksKeyError, type Mode } from "../src/internal/transport/transport.js";
import type { Fetch, OnVerification, VerificationAttempt } from "../src/options.js";
import { createRouterHTTPClient } from "../src/router-client.js";
import type { Trust } from "../src/trust.js";
import { KEY_SPKI_FP_SHA256_V1_FORMAT, VerificationError, type SevSnpMeasurement, type VerificationReport, type VerifiedFacts, type Verifier } from "../../verifier/src/index.js";
import { ReportBuilder } from "../../verifier/src/report.js";
import { verifiedFactsOf } from "../../verifier/src/verification.js";
import { TEST_CERT, TEST_PIN } from "./helpers/tls-server.js";

const HOST = "enclave.example";
const AUTHORIZED: Trust = { kind: "authorizedBy", authorize: () => undefined };
const METADATA = { verifier: { name: "test", version: "0" }, verifiedAt: new Date("2026-01-01T00:00:00Z") };
const LAYERS = ["envelope", "provenance", "quote", "policy"];

/** A real report of a verification that passed, endorsing `tls` and valid for a minute. */
function passed(tls: string = TEST_PIN): VerificationReport {
  const b = new ReportBuilder();
  for (const layer of LAYERS) b.passed(layer);
  const facts = verifiedFactsOf({
    codeDigest: "11".repeat(32),
    codeTag: "v1",
    configRepo: "org/repo",
    codeMeasurement: { platform: "sev-snp", launch: new Uint8Array(48).fill(1) },
    enclaveMeasurement: { platform: "sev-snp", launch: new Uint8Array(48).fill(1) },
    cryptoMaterial: [{ id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: tls }],
    freshnessExpiresAt: new Date(Date.now() + 60_000),
  });
  return b.passedAll(facts, METADATA);
}

/** The verifier's rejection at the policy step, with its report. */
function rejection(): VerificationError {
  const b = new ReportBuilder();
  b.passed("envelope");
  b.passed("provenance");
  b.passed("quote");
  b.measured = { tlsPublicKeyFP: TEST_PIN, cpu: { measurement: { platform: "sev-snp", launch: new Uint8Array(48).fill(2) } } };
  const report = b.failed("policy", "launch measurement mismatch", METADATA);
  return new VerificationError("launch measurement mismatch", { layer: "policy", report });
}

/** A verifier that answers each verification with the next of `outcomes`, repeating the last; "reject" throws {@link rejection}. */
function scripted(outcomes: ("pass" | "reject" | VerificationReport)[]): Verifier & { calls: number } {
  const v = {
    calls: 0,
    checkPinVerifiability: () => {},
    verifyV3At: async () => {
      const outcome = outcomes[Math.min(v.calls++, outcomes.length - 1)]!;
      if (outcome === "reject") throw rejection();
      return outcome === "pass" ? passed() : outcome;
    },
  };
  return v as unknown as Verifier & { calls: number };
}

/** Records every call of the `onVerification` option. */
function recorder(): { calls: { host: string; report?: VerificationReport; error?: TinfoilError }[]; onVerification: OnVerification } {
  const calls: { host: string; report?: VerificationReport; error?: TinfoilError }[] = [];
  return { calls, onVerification: (host, report, error) => void calls.push({ host, ...(report === undefined ? {} : { report }), ...(error === undefined ? {} : { error }) }) };
}

/** A document fetch that serves a placeholder document, or fails with 503 while `down` is set. */
function documents(): { fetch: Fetch; down: boolean } {
  const state: { fetch: Fetch; down: boolean } = {
    down: false,
    fetch: async () => (state.down ? new Response("", { status: 503, statusText: "Service Unavailable" }) : new Response(new Uint8Array([1]))),
  };
  return state;
}

const lastOf = <T>(items: readonly T[]): T | undefined => items[items.length - 1];

function seams(verifier: Verifier, fetch: Fetch): EnclaveClientSeams {
  return { verifier, documentFetch: fetch, sleep: async () => {}, tls: { ca: TEST_CERT } };
}

/** The verifier's VerificationError in `err`'s cause chain, if any. */
function verificationErrorIn(err: unknown): VerificationError | undefined {
  for (let e = err; e instanceof Error; e = (e as { cause?: unknown }).cause) {
    if (e instanceof VerificationError) return e;
  }
  return undefined;
}

describe("verification reports from the clients", () => {
  it("reports an initial verification that succeeds, once, with the enclave's host and the same report", async () => {
    const r = recorder();
    const client = await createEnclaveHTTPClient(HOST, AUTHORIZED, { onVerification: r.onVerification }, seams(scripted(["pass"]), documents().fetch));
    const last = client.lastVerification();
    expect(last?.error).toBeUndefined();
    expect(last?.report?.verifiedFacts?.tlsPublicKeyFP).toBe(TEST_PIN);
    expect(last?.report?.steps.map((s) => s.status)).toEqual(["passed", "passed", "passed", "passed"]);
    expect(r.calls).toHaveLength(1);
    expect(r.calls[0]!.host).toBe(HOST);
    expect(r.calls[0]!.error).toBeUndefined();
    expect(r.calls[0]!.report!.toJSON()).toEqual(last!.report!.toJSON());
    expect((await client.ensureVerified()).toJSON()).toEqual(last!.report!.toJSON());
    await client.close();
  });

  it("reports a rejected document as an attestation error from which the verifier's error and its report are reachable", async () => {
    const r = recorder();
    const client = await createEnclaveHTTPClient(HOST, AUTHORIZED, { onVerification: r.onVerification }, seams(scripted(["pass", "reject"]), documents().fetch));
    const err = await client.reverify().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AttestationError);
    expect(findTinfoilError(err)).toBe(err);
    const rejected = verificationErrorIn(err);
    expect(rejected?.layer).toBe("policy");
    expect(rejected?.report.failedStep()?.layer).toBe("policy");
    expect(rejected?.report.verifiedFacts).toBeUndefined();
    expect(rejected?.report.partialFacts?.measured?.cpu).toBeDefined();
    // The same error, and no report, from both.
    expect(client.lastVerification()?.error).toBe(err);
    expect(client.lastVerification()?.report).toBeUndefined();
    expect(lastOf(r.calls)).toEqual({ host: HOST, error: err });
    await client.close();
  });

  it("reports a failed attestation fetch as a network error with no report", async () => {
    const r = recorder();
    const docs = documents();
    const client = await createEnclaveHTTPClient(HOST, AUTHORIZED, { onVerification: r.onVerification }, seams(scripted(["pass"]), docs.fetch));
    docs.down = true;
    const err = await client.reverify().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NetworkError);
    expect(verificationErrorIn(err)).toBeUndefined();
    expect(client.lastVerification()?.error).toBe(err);
    expect(lastOf(r.calls)).toEqual({ host: HOST, error: err });
    await client.close();
  });

  it("returns the failure of a re-verification, not the earlier success", async () => {
    const client = await createEnclaveHTTPClient(HOST, AUTHORIZED, {}, seams(scripted(["pass", "reject"]), documents().fetch));
    expect(client.lastVerification()?.report).toBeDefined();
    await expect(client.reverify()).rejects.toBeInstanceOf(AttestationError);
    expect(client.lastVerification()?.report).toBeUndefined();
    expect(client.lastVerification()?.error).toBeInstanceOf(AttestationError);
    await client.close();
  });

  it("reports both attempts when a verification fails and its retry succeeds, and returns the second", async () => {
    const r = recorder();
    const verifier = scripted(["reject", "pass"]);
    const client = await createEnclaveHTTPClient(HOST, AUTHORIZED, { onVerification: r.onVerification }, seams(verifier, documents().fetch));
    expect(verifier.calls).toBe(2);
    expect(r.calls.map((c) => [c.host, c.report !== undefined, c.error !== undefined])).toEqual([
      [HOST, false, true],
      [HOST, true, false],
    ]);
    expect(verificationErrorIn(r.calls[0]!.error)?.report.failedStep()?.layer).toBe("policy");
    expect(client.lastVerification()?.report?.verifiedFacts?.tlsPublicKeyFP).toBe(TEST_PIN);
    await client.close();
  });

  it("reports the re-verification that a key rotation triggers, with the same host", async () => {
    const r = recorder();
    let key = "k1";
    const verifier = scripted([passed("k1"), passed("k2")]);
    const enclave = await Enclave.create({ host: HOST, pin: {}, verifier, fetch: documents().fetch, sleep: async () => {}, onVerification: r.onVerification });
    const mode: Mode = {
      name: "tls",
      validateRequest: () => {},
      bind: (v: VerifiedFacts) => ({
        fetch: async () => {
          if (v.tlsPublicKeyFP !== key) throw new PeerLacksKeyError("peer changed key");
          return new Response(key);
        },
      }),
    };
    const t = new KeyedTransport(enclave, mode);
    expect(await (await t.fetch(`https://${HOST}/`)).text()).toBe("k1");
    key = "k2";
    await expect(t.fetch(`https://${HOST}/`)).rejects.toBeInstanceOf(KeyRejectionError);
    // The rejection binds no channel, so it is no attempt; the re-verification that it triggers is.
    expect(r.calls).toHaveLength(1);
    expect(await (await t.fetch(`https://${HOST}/`)).text()).toBe("k2");
    expect(r.calls.map((c) => [c.host, c.report?.verifiedFacts?.tlsPublicKeyFP])).toEqual([
      [HOST, "k1"],
      [HOST, "k2"],
    ]);
    t.close();
  });

  it("reports a verification that concurrent requests share once", async () => {
    const r = recorder();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const fetch: Fetch = async () => {
      await gate;
      return new Response(new Uint8Array([1]));
    };
    const enclave = await Enclave.create({ host: HOST, pin: {}, verifier: scripted(["pass"]), fetch, onVerification: r.onVerification });
    const t = new KeyedTransport(enclave, { name: "tls", validateRequest: () => {}, bind: () => ({ fetch: async () => new Response("ok") }) });
    const waiters = [t.ensureVerified(), t.ensureVerified(), t.reverify(), t.fetch(`https://${HOST}/`)];
    release();
    await Promise.all(waiters);
    expect(r.calls).toHaveLength(1);
    t.close();
  });

  it("reports each router that discovery tries with its own host, and describes the chosen one", async () => {
    const r = recorder();
    const verifier = {
      checkPinVerifiability: () => {},
      verifyV3At: async () => (lastOf(seen) === "bad.example" ? Promise.reject(rejection()) : passed()),
    } as unknown as Verifier;
    const seen: string[] = [];
    const documentFetch: Fetch = async (input) => {
      seen.push(new URL(String(input)).host);
      return new Response(new Uint8Array([1]));
    };
    const client = await createRouterHTTPClient(
      { transport: { kind: "tls" }, onVerification: r.onVerification },
      { verifier, documentFetch, routersFetch: async () => new Response(JSON.stringify(["bad.example", "good.example"])), shuffle: (items) => [...items], sleep: async () => {}, tls: { ca: TEST_CERT }, resolveSecret: () => "secret" },
    );
    expect(client.enclave).toBe("good.example");
    expect(r.calls.map((c) => [c.host, c.report !== undefined])).toEqual([
      ["bad.example", false],
      ["good.example", true],
    ]);
    expect(verificationErrorIn(r.calls[0]!.error)?.layer).toBe("policy");
    expect(client.lastVerification()?.report?.toJSON()).toEqual(r.calls[1]!.report!.toJSON());
    await client.close();
  });

  it("gives the verification check verified facts, and never a failed verification", async () => {
    const checked: VerifiedFacts[] = [];
    const client = await createEnclaveHTTPClient(HOST, AUTHORIZED, { verificationCheck: (facts) => void checked.push(facts) }, seams(scripted(["reject", "pass"]), documents().fetch));
    expect(checked).toHaveLength(1);
    expect(checked[0]!.tlsPublicKeyFP).toBe(TEST_PIN);
    expect(checked[0]).not.toHaveProperty("steps");
    await client.close();
  });

  it("lets the callback call the client, and returns it the attempt that it was called for or a later one", async () => {
    let client: Awaited<ReturnType<typeof createEnclaveHTTPClient>> | undefined;
    const calls: { given: VerificationAttempt; seen: VerificationAttempt | undefined }[] = [];
    const ensured: Promise<VerificationReport>[] = [];
    const onVerification: OnVerification = (_host, report, error) => {
      if (client === undefined) return;
      calls.push({ given: report === undefined ? { error: error! } : { report }, seen: client.lastVerification() });
      // A call that would wait for a refresh in flight doesn't wait for the one that is reporting.
      if (report !== undefined) ensured.push(client.ensureVerified());
    };
    // The re-verification fails, and so does its retry; the next one passes.
    client = await createEnclaveHTTPClient(HOST, AUTHORIZED, { onVerification }, seams(scripted(["pass", "reject", "reject", "pass"]), documents().fetch));
    const failure = await client.reverify().catch((e: unknown) => e);
    expect(failure).toBeInstanceOf(AttestationError);
    expect(calls).toHaveLength(2);
    // The retried attempt is reported once the retry decided the refresh, so the client already returns the later attempt.
    expect(calls[0]!.given.error).toBeInstanceOf(AttestationError);
    expect(calls[0]!.given.error).not.toBe(failure);
    expect(calls[0]!.seen).toEqual({ error: failure });
    expect(calls[1]!.given).toEqual({ error: failure });
    expect(calls[1]!.seen).toEqual({ error: failure });
    const report = await client.reverify();
    expect(calls).toHaveLength(3);
    expect(calls[2]!.given.report?.toJSON()).toEqual(report.toJSON());
    expect(calls[2]!.seen?.report?.toJSON()).toEqual(report.toJSON());
    expect(ensured).toHaveLength(1);
    expect((await ensured[0]!)?.toJSON()).toEqual(report.toJSON());
    await client.close();
  });

  it("keeps its state and later reports when a caller mutates a report it was given", async () => {
    let given: VerificationReport | undefined;
    const client = await createEnclaveHTTPClient(HOST, AUTHORIZED, { onVerification: (_h, report) => void (given = report) }, seams(scripted(["pass"]), documents().fetch));
    const original = client.lastVerification()!.report!.toJSON();
    for (const report of [client.lastVerification()!.report!, await client.ensureVerified(), given!]) {
      expect(Object.isFrozen(report)).toBe(true);
      expect(() => {
        (report.steps[0] as { status: string }).status = "failed";
      }).toThrow(TypeError);
      expect(() => {
        (report as { verifiedFacts?: unknown }).verifiedFacts = undefined;
      }).toThrow(TypeError);
      // The bytes and dates that can't be frozen are the caller's own copies.
      (report.verifiedFacts!.enclaveMeasurement as SevSnpMeasurement).launch.fill(0xff);
      report.metadata.verifiedAt.setFullYear(1999);
      report.verifiedFacts!.freshnessExpiresAt!.setFullYear(1999);
    }
    expect(client.lastVerification()!.report!.toJSON()).toEqual(original);
    expect((await client.ensureVerified()).toJSON()).toEqual(original);
    // The attempt itself is a new frozen object on each call.
    expect(client.lastVerification()).not.toBe(client.lastVerification());
    expect(Object.isFrozen(client.lastVerification())).toBe(true);
    await client.close();
  });

  it("records no attempt for a request that fails before verifying, and keeps reporting after a close", async () => {
    const r = recorder();
    const client = await createEnclaveHTTPClient(HOST, AUTHORIZED, { onVerification: r.onVerification }, seams(scripted(["pass"]), documents().fetch));
    await expect(client.fetch("https://other.example/")).rejects.toBeInstanceOf(ConfigurationError);
    expect(r.calls).toHaveLength(1);
    await client.close();
    expect(client.lastVerification()?.report).toBeDefined();
  });
});
