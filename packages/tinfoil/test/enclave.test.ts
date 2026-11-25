/**
 * Enclave verification: a document fetched with a fresh nonce and verified
 * under the policy, the retry, the verification check, the transport-key
 * requirement, and the cache that shares one verification among callers and
 * refreshes it when it expires or is invalidated. The vector-backed cases
 * serve golden documents from a mocked fetch under the vector's injected
 * roots and clock; the live case verifies a production enclave.
 */
import { AttestationError, ConfigurationError, NetworkError } from "../src/errors.js";
import { Enclave, fromVerify, RejectedError, VERIFICATION_RETRY_DELAY_MS, type EnclaveConfig } from "../src/internal/enclave.js";
import { VerifiedEnclave } from "../src/internal/verified.js";
import { verifiedReport } from "./helpers/report.js";
import type { Fetch } from "../src/options.js";
import { dangerousTestOnlyVerifier } from "../../verifier/conformance/testing.js";
import { KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, UsageError, VerificationError, type VerifiedFacts, type Verifier } from "../../verifier/src/index.js";
import { ReportBuilder } from "../../verifier/src/report.js";
import { conformanceAvailable, inputBytes, loadFixture, vectorsTitle, type ConformanceFixture } from "../../verifier/test/helpers/conformance.js";
import { clockOf, rootsOf } from "../../verifier/test/helpers/verify.js";
import { beforeAll, describe, expect, it, vi } from "vitest";

const RUN_INTEGRATION = process.env.RUN_TINFOIL_INTEGRATION === "true";
const HOST = "enclave.example";

const hex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));
const noBinding = (): undefined => undefined;

/** The report of a verification that the quote step rejected. */
const rejectedAtQuote = () => new ReportBuilder().failed("quote", "bad report", { verifier: { name: "", version: "" }, verifiedAt: new Date(0) });

/** A vector served from a mocked fetch: the document, the nonce it is bound to, the clock, and the verifier under its roots. */
interface Served {
  fixture: ConformanceFixture;
  verifier: Verifier;
  document: Uint8Array<ArrayBuffer>;
  nonce: Uint8Array;
  at: Date;
  expected: { codeDigest: string; tls: string; hpke: string };
}

async function serve(relPath: string): Promise<Served> {
  const fixture = loadFixture(relPath);
  const e = fixture.expected as Record<string, string | undefined>;
  return {
    fixture,
    verifier: await dangerousTestOnlyVerifier(rootsOf(fixture)),
    document: new Uint8Array(inputBytes(fixture, "document_b64")),
    nonce: hex(fixture.input.nonce_hex as string),
    at: clockOf(fixture),
    expected: { codeDigest: e.code_digest ?? "", tls: e.tls_public_key_fp ?? "", hpke: e.hpke_public_key ?? "" },
  };
}

/** A fetch answering from a queue of responses, the last one repeating, recording the URLs asked. */
function serving(responses: (() => Response)[]): { fetch: Fetch; urls: string[] } {
  const urls: string[] = [];
  const fetch: Fetch = async (input) => {
    urls.push(String(input));
    const next = responses.length > 1 ? responses.shift()! : responses[0]!;
    return next();
  };
  return { fetch, urls };
}

/** A fetch that serves `document` only once `release` is called, so callers can be lined up first. */
function gated(document: Uint8Array<ArrayBuffer>): { fetch: Fetch; urls: string[]; release: () => void } {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => (release = resolve));
  const inner = serving([() => new Response(document)]);
  const fetch: Fetch = async (input, init) => {
    await gate;
    return inner.fetch(input, init);
  };
  return { fetch, urls: inner.urls, release };
}

const noSleep = { slept: [] as number[], sleep: async (ms: number): Promise<void> => void noSleep.slept.push(ms) };

/** A verifier whose verification carries only the given crypto material, for the transport-key rules. */
function stubVerifier(material: { id: string; format: string; data: string }[], expiresAt: Date): Verifier {
  const verification = {
    cryptoMaterial: material.map((m) => ({ ...m })),
    cryptoMaterialData: (id: string, format: string) => material.find((m) => m.id === id && m.format === format)?.data,
    tlsPublicKeyFP: material.find((m) => m.id === "tls" && m.format === KEY_SPKI_FP_SHA256_V1_FORMAT)?.data,
    hpkePublicKey: material.find((m) => m.id === "hpke" && m.format === KEY_X25519_HPKE_V1_FORMAT)?.data,
    freshnessExpiresAt: new Date(expiresAt.getTime()),
  } as unknown as VerifiedFacts;
  return {
    checkPinVerifiability: () => {},
    verifyV3At: async () => verifiedReport(verification),
  } as unknown as Verifier;
}

describe("fromVerify", () => {
  it("reports a usage error as configuration and any other rejection as attestation, keeping the cause", () => {
    const usage = fromVerify(new UsageError("bad pin"));
    expect(usage).toBeInstanceOf(ConfigurationError);
    expect(usage.cause).toBeInstanceOf(UsageError);
    const verification = new VerificationError("bad report", { layer: "quote", report: rejectedAtQuote() });
    const rejected = fromVerify(verification);
    expect(rejected).toBeInstanceOf(AttestationError);
    expect(rejected.message).toBe("attestation error: verification error: quote: bad report");
    // The rejection's report stays reachable through the cause.
    expect(rejected.cause).toBe(verification);
    expect((rejected.cause as VerificationError).report.failedStep()?.layer).toBe("quote");
    expect(fromVerify(new NetworkError("down"))).toBeInstanceOf(NetworkError);
  });

  it("classifies a usage error from another loaded copy of the verifier package", async () => {
    // A duplicate install evaluates the verifier's modules a second time, so its classes are different objects.
    vi.resetModules();
    const other = await import("../../verifier/src/errors.js");
    expect(other.UsageError).not.toBe(UsageError);
    const usage = fromVerify(new other.UsageError("bad pin"));
    expect(usage).toBeInstanceOf(ConfigurationError);
    expect(usage.message).toBe("configuration error: usage error: bad pin");
    expect(usage.cause).toBeInstanceOf(other.UsageError);
    expect(fromVerify(new other.VerificationError("bad report", { layer: "quote", report: rejectedAtQuote() }))).toBeInstanceOf(AttestationError);
    // A copy old enough to carry no brand is recognized by the error's name.
    const unbranded = Object.assign(new Error("usage error: bad pin"), { name: "UsageError" });
    expect(fromVerify(unbranded)).toBeInstanceOf(ConfigurationError);
    expect(fromVerify(Object.assign(new Error("bad report"), { name: "VerificationError" }))).toBeInstanceOf(AttestationError);
  });
});

describe.skipIf(!conformanceAvailable())(vectorsTitle("Enclave"), () => {
  let golden: Served;
  beforeAll(async () => {
    golden = await serve("golden/golden-happy.json");
  });

  function config(overrides: Partial<EnclaveConfig> & { fetch: Fetch }): EnclaveConfig {
    return {
      host: HOST,
      pin: { repo: golden.fixture.input.repo as string },
      verifier: golden.verifier,
      clock: () => golden.at,
      nonce: () => golden.nonce,
      sleep: noSleep.sleep,
      ...overrides,
    };
  }

  it("verifies the document it fetches with the nonce and reports the endorsed facts", async () => {
    const { fetch, urls } = serving([() => new Response(golden.document)]);
    const enclave = await Enclave.create(config({ fetch }));
    const v = (await enclave.verify()).verifiedFacts;
    expect(urls).toEqual([`https://${HOST}/.well-known/tinfoil-attestation?nonce=${golden.fixture.input.nonce_hex}`]);
    expect(v.codeDigest).toBe(golden.expected.codeDigest);
    expect(v.tlsPublicKeyFP).toBe(golden.expected.tls);
    expect(v.hpkePublicKey).toBe(golden.expected.hpke);
    expect(v.freshnessExpiresAt!.getTime()).toBeGreaterThan(golden.at.getTime());
    expect(enclave.host()).toBe(HOST);
    expect(enclave.pin()).toEqual({ repo: golden.fixture.input.repo, project: "" });
    expect(enclave.verifier()).toBe(golden.verifier);
  });

  it("fetches through a relay when one is configured, under the relay's path", async () => {
    for (const [relayURL, want] of [
      ["https://relay.example/", "https://relay.example/.well-known/tinfoil-attestation"],
      ["https://relay.example/mount/", "https://relay.example/mount/.well-known/tinfoil-attestation"],
    ] as const) {
      const { fetch, urls } = serving([() => new Response(golden.document)]);
      await (await Enclave.create(config({ fetch, relayURL }))).verify();
      expect(urls[0]).toBe(`${want}?nonce=${golden.fixture.input.nonce_hex}&enclave=${HOST}`);
    }
  });

  it("rejects a document bound to another nonce as an attestation error, after one retry", async () => {
    noSleep.slept.length = 0;
    const { fetch, urls } = serving([() => new Response(golden.document)]);
    const enclave = await Enclave.create(config({ fetch, nonce: () => new Uint8Array(32) }));
    const err = await enclave.verify().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AttestationError);
    expect((err as Error).message).toMatch(/\(first attempt: attestation error: /);
    expect(urls).toHaveLength(2);
    expect(noSleep.slept).toEqual([VERIFICATION_RETRY_DELAY_MS]);
  });

  it("rejects a document the policy rejects", async () => {
    const rejected = await serve("golden/i5-not-endorsed.json");
    const { fetch } = serving([() => new Response(rejected.document)]);
    const enclave = await Enclave.create(config({ fetch, verifier: rejected.verifier, nonce: () => rejected.nonce, clock: () => rejected.at }));
    await expect(enclave.verifyOnce()).rejects.toBeInstanceOf(AttestationError);
  });

  it("requires the TLS key and a well-formed HPKE key a transport binds traffic to", async () => {
    const noTls = await serve("golden/e-missing-tls-key.json");
    const missing = await Enclave.create(config({ fetch: serving([() => new Response(noTls.document)]).fetch, verifier: noTls.verifier, nonce: () => noTls.nonce, clock: () => noTls.at }));
    const missingErr = await missing.verifyOnce().catch((e: unknown) => e);
    expect(missingErr).toBeInstanceOf(AttestationError);
    expect((missingErr as Error).message).toBe('attestation error: document endorses no "tls" key');

    const badHpke = await serve("golden/e-hpke-wrong-format.json");
    const malformed = await Enclave.create(config({ fetch: serving([() => new Response(badHpke.document)]).fetch, verifier: badHpke.verifier, nonce: () => badHpke.nonce, clock: () => badHpke.at }));
    const malformedErr = await malformed.verifyOnce().catch((e: unknown) => e);
    expect(malformedErr).toBeInstanceOf(AttestationError);
    expect((malformedErr as Error).message).toMatch(/^attestation error: crypto_material item "hpke" has format ".*", want "https:\/\/tinfoil.sh\/key\/x25519-hpke\/v1"$/);
  });

  it("accepts a document that endorses no HPKE key and rejects a TLS key in another format", async () => {
    const later = new Date(golden.at.getTime() + 60_000);
    const tlsOnly = stubVerifier([{ id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: "ab".repeat(32) }], later);
    const { fetch } = serving([() => new Response(golden.document)]);
    const v = (await (await Enclave.create(config({ fetch, verifier: tlsOnly }))).verifyOnce()).verifiedFacts;
    expect(v.tlsPublicKeyFP).toBe("ab".repeat(32));
    expect(v.hpkePublicKey).toBeUndefined();

    const oddTls = stubVerifier([{ id: "tls", format: "https://example.com/other", data: "x" }], later);
    const err = await (await Enclave.create(config({ fetch, verifier: oddTls }))).verifyOnce().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AttestationError);
    expect((err as Error).message).toMatch(/crypto_material item "tls" has format "https:\/\/example.com\/other"/);
  });

  it("rejects a verification whose freshness window is already closed", async () => {
    const expired = stubVerifier([{ id: "tls", format: KEY_SPKI_FP_SHA256_V1_FORMAT, data: "ab".repeat(32) }], golden.at);
    const { fetch } = serving([() => new Response(golden.document)]);
    await expect((await Enclave.create(config({ fetch, verifier: expired }))).verifyOnce()).rejects.toThrow(/freshness witnesses have expired/);
  });

  it("retries once after a network failure and reports the terminal failure with the first", async () => {
    noSleep.slept.length = 0;
    const recovered = serving([() => new Response("busy", { status: 503, statusText: "Service Unavailable" }), () => new Response(golden.document)]);
    const v = (await (await Enclave.create(config({ fetch: recovered.fetch }))).verify()).verifiedFacts;
    expect(v.tlsPublicKeyFP).toBe(golden.expected.tls);
    expect(recovered.urls).toHaveLength(2);
    expect(noSleep.slept).toEqual([VERIFICATION_RETRY_DELAY_MS]);

    const down = serving([() => new Response("", { status: 503, statusText: "Service Unavailable" }), () => new Response("", { status: 500, statusText: "Internal Server Error" })]);
    const err = await (await Enclave.create(config({ fetch: down.fetch }))).verify().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NetworkError);
    expect((err as Error).message).toMatch(/^network error: HTTP GET .*: 500 Internal Server Error \(first attempt: network error: HTTP GET .*: 503 Service Unavailable\)$/);
    expect(down.urls).toHaveLength(2);
  });

  it("rejects the repository's document when only a registry project of that name is pinned", async () => {
    const { fetch } = serving([() => new Response(golden.document)]);
    const enclave = await Enclave.create(config({ fetch, pin: { project: (golden.fixture.input.repo as string).toLowerCase() } }));
    await expect(enclave.verifyOnce()).rejects.toThrow(/only a registry project is pinned/);
    await expect(enclave.verifyOnce()).rejects.toBeInstanceOf(AttestationError);
  });

  it("does not retry without the retry, and does not retry a bad repository pin at all", async () => {
    const down = serving([() => new Response("", { status: 503 })]);
    await expect((await Enclave.create(config({ fetch: down.fetch }))).verifyOnce()).rejects.toBeInstanceOf(NetworkError);
    expect(down.urls).toHaveLength(1);

    const { fetch, urls } = serving([() => new Response(golden.document)]);
    await expect(Enclave.create(config({ fetch, pin: { repo: "not a repository" } }))).rejects.toBeInstanceOf(ConfigurationError);
    // A bare reference from untyped code is refused instead of being read as an empty pin.
    await expect(Enclave.create(config({ fetch, pin: golden.fixture.input.repo as unknown as EnclaveConfig["pin"] }))).rejects.toBeInstanceOf(ConfigurationError);
    await expect(Enclave.create(config({ fetch, host: "" }))).rejects.toThrow(/enclave host is required/);
    expect(urls).toHaveLength(0);
  });

  it("runs the verification check after the policy and does not retry its rejection", async () => {
    const seen: string[] = [];
    const { fetch, urls } = serving([() => new Response(golden.document)]);
    const accepting = await Enclave.create(config({ fetch, verificationCheck: (v) => void seen.push(v.tlsPublicKeyFP!) }));
    await accepting.verify();
    expect(seen).toEqual([golden.expected.tls]);

    const rejecting = await Enclave.create(
      config({
        fetch,
        verificationCheck: async () => {
          throw new Error("not this one");
        },
      }),
    );
    const err = await rejecting.verify().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RejectedError);
    expect(err).toBeInstanceOf(AttestationError);
    expect((err as Error).message).toBe(`attestation error: verification check rejected ${HOST}: not this one`);
    expect(urls).toHaveLength(2);
  });

  it("stops at an aborted signal before fetching", async () => {
    const { fetch, urls } = serving([() => new Response(golden.document)]);
    const enclave = await Enclave.create(config({ fetch }));
    const controller = new AbortController();
    controller.abort(new Error("stop"));
    await expect(enclave.verify(controller.signal)).rejects.toThrow(/stop/);
    expect(urls).toHaveLength(0);
  });

  it("reports a caller's abort during the fetch as the caller's own reason", async () => {
    // A fetch that fails the way fetch does once its signal aborts: with the reason, which the document fetch reports as a network failure.
    const fetch: Fetch = (_input, init) => new Promise((_, reject) => init!.signal!.addEventListener("abort", () => reject(init!.signal!.reason), { once: true }));
    const enclave = await Enclave.create(config({ fetch }));
    const controller = new AbortController();
    const pending = enclave.verify(controller.signal);
    const reason = new Error("gave up");
    controller.abort(reason);
    await expect(pending).rejects.toBe(reason);
  });

  describe("VerifiedEnclave", () => {
    it("verifies on first use, serves the cached verification while fresh, and refreshes once it expires", async () => {
      let now = golden.at;
      const { fetch, urls } = serving([() => new Response(golden.document)]);
      const bound: VerifiedFacts[] = [];
      const cache = new VerifiedEnclave(
        await Enclave.create(config({ fetch, clock: () => now })),
        (v) => {
          bound.push(v);
          return bound.length;
        },
        () => now,
      );
      expect(cache.lastVerificationAttempt()).toBeUndefined();
      expect(urls).toHaveLength(0);

      const first = await cache.ensureVerified();
      expect(first.report.verifiedFacts.tlsPublicKeyFP).toBe(golden.expected.tls);
      expect(first.bound).toBe(1);
      expect(bound[0]).toBe(first.report.verifiedFacts);
      expect(cache.lastVerificationAttempt()?.report?.toJSON()).toEqual(first.report.toJSON());
      expect(await cache.ensureVerified()).toBe(first);
      expect(urls).toHaveLength(1);

      const again = await cache.reverify();
      expect(again).not.toBe(first);
      expect(urls).toHaveLength(2);

      // Past the window the cache verifies again; at this clock the policy
      // rejects the stale witnesses, so the refresh fails, and the last
      // attempt is that failure rather than the earlier success.
      now = new Date(again.report.verifiedFacts.freshnessExpiresAt!.getTime() + 1);
      const failure = await cache.ensureVerified().catch((e: unknown) => e);
      expect(failure).toBeInstanceOf(AttestationError);
      expect(urls).toHaveLength(4);
      expect(cache.lastVerificationAttempt()).toEqual({ error: failure });
    });

    it("verifies again after a state is invalidated, and ignores invalidation of a replaced state", async () => {
      const { fetch, urls } = serving([() => new Response(golden.document)]);
      const cache = new VerifiedEnclave(await Enclave.create(config({ fetch })), noBinding, () => golden.at);
      const first = await cache.ensureVerified();
      const second = await cache.reverify();
      cache.invalidate(first);
      expect(await cache.ensureVerified()).toBe(second);
      cache.invalidate(second);
      const third = await cache.ensureVerified();
      expect(third).not.toBe(second);
      expect(urls).toHaveLength(3);
    });

    it("shares one verification among concurrent callers, including its failure", async () => {
      const { fetch, urls, release } = gated(golden.document);
      const cache = new VerifiedEnclave(await Enclave.create(config({ fetch })), noBinding, () => golden.at);
      const waiters = [cache.ensureVerified(), cache.ensureVerified(), cache.reverify()];
      release();
      const states = await Promise.all(waiters);
      expect(new Set(states).size).toBe(1);
      expect(urls).toHaveLength(1);

      const failing = new VerifiedEnclave(await Enclave.create(config({ fetch: serving([() => new Response("", { status: 500 })]).fetch })), noBinding, () => golden.at);
      const results = await Promise.allSettled([failing.ensureVerified(), failing.ensureVerified()]);
      expect(results.map((r) => r.status)).toEqual(["rejected", "rejected"]);
      expect((results[0] as PromiseRejectedResult).reason).toBe((results[1] as PromiseRejectedResult).reason);
    });

    it("lets a caller stop waiting without aborting the verification others need", async () => {
      const { fetch, urls, release } = gated(golden.document);
      const cache = new VerifiedEnclave(await Enclave.create(config({ fetch })), noBinding, () => golden.at);
      const controller = new AbortController();
      const impatient = cache.ensureVerified(controller.signal);
      const patient = cache.ensureVerified();
      controller.abort(new Error("impatient"));
      await expect(impatient).rejects.toThrow(/impatient/);
      release();
      expect((await patient).report.verifiedFacts.tlsPublicKeyFP).toBe(golden.expected.tls);
      expect(urls).toHaveLength(1);
    });

    it("lets a one-shot probe give up without aborting the verification a concurrent caller joined", async () => {
      const { fetch, urls, release } = gated(golden.document);
      const cache = new VerifiedEnclave(await Enclave.create(config({ fetch })), noBinding, () => golden.at);
      const budget = new AbortController();
      const probe = cache.verifyOnce(budget.signal);
      const request = cache.ensureVerified();
      budget.abort(new Error("budget spent"));
      await expect(probe).rejects.toThrow(/budget spent/);
      release();
      expect((await request).report.verifiedFacts.tlsPublicKeyFP).toBe(golden.expected.tls);
      expect(cache.lastVerificationAttempt()?.report).toBeDefined();
      expect(urls).toHaveLength(1);
    });
  });
});

describe("Enclave against a live enclave", () => {
  it.skipIf(!RUN_INTEGRATION)("verifies inference.tinfoil.sh under the embedded roots", async () => {
    const enclave = await Enclave.create({ host: "inference.tinfoil.sh", pin: { repo: "tinfoilsh/confidential-model-router", project: "tinfoilsh/confidential-model-router" } });
    const v = (await enclave.verify()).verifiedFacts;
    expect(v.tlsPublicKeyFP).toMatch(/^[0-9a-f]{64}$/);
    expect(v.hpkePublicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(v.freshnessExpiresAt!.getTime()).toBeGreaterThan(Date.now());
    const cache = new VerifiedEnclave(enclave, noBinding);
    const state = await cache.ensureVerified();
    expect(cache.lastVerificationAttempt()?.report?.verifiedFacts?.tlsPublicKeyFP).toBe(state.report.verifiedFacts.tlsPublicKeyFP);
  }, 120_000);
});
