/**
 * Enclave verification: a document fetched with a fresh nonce and verified
 * under the policy, the retry, the verification check, the transport-key
 * requirement, and the cache that shares one verification among callers and
 * refreshes it when it expires or is invalidated. The vector-backed cases
 * serve a golden document from a mocked fetch under the vector's injected
 * roots and clock; the live case verifies a production enclave.
 */
import { AttestationError, ConfigurationError, NetworkError } from "../../src/v3/errors.js";
import { Enclave, RejectedError, VERIFICATION_RETRY_DELAY_MS, type EnclaveConfig } from "../../src/v3/internal/enclave.js";
import { VerifiedEnclave } from "../../src/v3/internal/verified.js";
import type { Fetch } from "../../src/v3/options.js";
import { dangerousTestOnlyVerifier } from "../../../verifier/src/v3/verifier.js";
import type { Verification, Verifier } from "../../../verifier/src/v3/index.js";
import { conformanceAvailable, inputBytes, loadFixture, vectorsTitle, type ConformanceFixture } from "../../../verifier/test/v3/helpers/conformance.js";
import { clockOf, rootsOf } from "../../../verifier/test/v3/helpers/verify.js";
import { beforeAll, describe, expect, it } from "vitest";

const RUN_INTEGRATION = process.env.RUN_TINFOIL_INTEGRATION === "true";
const HOST = "enclave.example";

const hex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));

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
  const e = fixture.expected as Record<string, string>;
  return {
    fixture,
    verifier: await dangerousTestOnlyVerifier(rootsOf(fixture)),
    document: new Uint8Array(inputBytes(fixture, "document_b64")),
    nonce: hex(fixture.input.nonce_hex as string),
    at: clockOf(fixture),
    expected: { codeDigest: e.code_digest!, tls: e.tls_public_key_fp!, hpke: e.hpke_public_key! },
  };
}

/** A fetch answering the enclave's attestation endpoint from a queue of responses; the last one repeats. */
function serving(responses: (() => Response)[]): { fetch: Fetch; urls: string[] } {
  const urls: string[] = [];
  const fetch: Fetch = async (input) => {
    urls.push(String(input));
    const next = responses.length > 1 ? responses.shift()! : responses[0]!;
    return next();
  };
  return { fetch, urls };
}

const noSleep = { slept: [] as number[], sleep: async (ms: number): Promise<void> => void noSleep.slept.push(ms) };

describe.skipIf(!conformanceAvailable())(vectorsTitle("Enclave"), () => {
  let golden: Served;
  beforeAll(async () => {
    golden = await serve("golden/golden-happy.json");
  });

  function config(overrides: Partial<EnclaveConfig> & { fetch: Fetch }): EnclaveConfig {
    return {
      host: HOST,
      repo: golden.fixture.input.repo as string,
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
    const v = await enclave.verify();
    expect(urls).toEqual([`https://${HOST}/.well-known/tinfoil-attestation?nonce=${golden.fixture.input.nonce_hex}`]);
    expect(v.codeDigest()).toBe(golden.expected.codeDigest);
    expect(v.tlsPublicKeyFP()).toBe(golden.expected.tls);
    expect(v.hpkePublicKey()).toBe(golden.expected.hpke);
    expect(v.freshnessExpiresAt()!.getTime()).toBeGreaterThan(golden.at.getTime());
    expect(enclave.host()).toBe(HOST);
    expect(enclave.repo()).toBe(golden.fixture.input.repo);
    expect(enclave.verifier()).toBe(golden.verifier);
  });

  it("fetches through a relay when one is configured", async () => {
    const { fetch, urls } = serving([() => new Response(golden.document)]);
    await (await Enclave.create(config({ fetch, relay: "relay.example" }))).verify();
    expect(urls[0]).toBe(`https://relay.example/.well-known/tinfoil-attestation?nonce=${golden.fixture.input.nonce_hex}&enclave=${HOST}`);
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

  it("retries once after a network failure and reports the terminal failure with the first", async () => {
    noSleep.slept.length = 0;
    const recovered = serving([() => new Response("busy", { status: 503, statusText: "Service Unavailable" }), () => new Response(golden.document)]);
    const v = await (await Enclave.create(config({ fetch: recovered.fetch }))).verify();
    expect(v.tlsPublicKeyFP()).toBe(golden.expected.tls);
    expect(recovered.urls).toHaveLength(2);
    expect(noSleep.slept).toEqual([VERIFICATION_RETRY_DELAY_MS]);

    const down = serving([() => new Response("", { status: 503, statusText: "Service Unavailable" }), () => new Response("", { status: 500, statusText: "Internal Server Error" })]);
    const err = await (await Enclave.create(config({ fetch: down.fetch }))).verify().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NetworkError);
    expect((err as Error).message).toMatch(/^network error: HTTP GET .*: 500 Internal Server Error \(first attempt: network error: HTTP GET .*: 503 Service Unavailable\)$/);
    expect(down.urls).toHaveLength(2);
  });

  it("does not retry without the retry, and does not retry a bad repository pin at all", async () => {
    const down = serving([() => new Response("", { status: 503 })]);
    await expect((await Enclave.create(config({ fetch: down.fetch }))).verifyOnce()).rejects.toBeInstanceOf(NetworkError);
    expect(down.urls).toHaveLength(1);

    const { fetch, urls } = serving([() => new Response(golden.document)]);
    await expect(Enclave.create(config({ fetch, repo: "not a repository" }))).rejects.toBeInstanceOf(ConfigurationError);
    await expect(Enclave.create(config({ fetch, host: "" }))).rejects.toThrow(/enclave host is required/);
    expect(urls).toHaveLength(0);
  });

  it("runs the verification check after the policy and does not retry its rejection", async () => {
    const seen: string[] = [];
    const { fetch, urls } = serving([() => new Response(golden.document)]);
    const accepting = await Enclave.create(config({ fetch, verificationCheck: (v) => void seen.push(v.tlsPublicKeyFP()!) }));
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

  describe("VerifiedEnclave", () => {
    it("verifies on first use, serves the cached verification while fresh, and refreshes once it expires", async () => {
      let now = golden.at;
      const { fetch, urls } = serving([() => new Response(golden.document)]);
      const bound: Verification[] = [];
      const cache = new VerifiedEnclave(
        await Enclave.create(config({ fetch, clock: () => now })),
        (v) => {
          bound.push(v);
          return bound.length;
        },
        () => now,
      );
      expect(cache.current()).toBeUndefined();
      expect(urls).toHaveLength(0);

      const first = await cache.ensureVerified();
      expect(first.verification.tlsPublicKeyFP()).toBe(golden.expected.tls);
      expect(first.bound).toBe(1);
      expect(bound[0]).toBe(first.verification);
      expect(cache.current()).toBe(first.verification);
      expect(await cache.ensureVerified()).toBe(first);
      expect(urls).toHaveLength(1);

      const again = await cache.reverify();
      expect(again).not.toBe(first);
      expect(urls).toHaveLength(2);

      // Past the window the cache verifies again; at this clock the policy
      // rejects the stale witnesses, so the refresh fails and the stale
      // verification stays current but is never served as valid.
      now = new Date(again.verification.freshnessExpiresAt()!.getTime() + 1);
      await expect(cache.ensureVerified()).rejects.toBeInstanceOf(AttestationError);
      expect(urls).toHaveLength(4);
      expect(cache.current()).toBe(again.verification);
    });

    it("verifies again after a state is invalidated, and ignores invalidation of a replaced state", async () => {
      const { fetch, urls } = serving([() => new Response(golden.document)]);
      const cache = new VerifiedEnclave(await Enclave.create(config({ fetch })), () => undefined, () => golden.at);
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
      let release!: () => void;
      const gate = new Promise<void>((resolve) => (release = resolve));
      const { fetch, urls } = serving([
        () => {
          throw new Error("unexpected");
        },
      ]);
      const slow: Fetch = async (input, init) => {
        await gate;
        return fetch(input, init);
      };
      const good = serving([() => new Response(golden.document)]);
      const slowGood: Fetch = async (input, init) => {
        await gate;
        return good.fetch(input, init);
      };
      const cache = new VerifiedEnclave(await Enclave.create(config({ fetch: slowGood })), () => undefined, () => golden.at);
      const waiters = [cache.ensureVerified(), cache.ensureVerified(), cache.reverify()];
      release();
      const states = await Promise.all(waiters);
      expect(new Set(states).size).toBe(1);
      expect(good.urls).toHaveLength(1);
      void slow;
      void urls;

      const failing = new VerifiedEnclave(await Enclave.create(config({ fetch: serving([() => new Response("", { status: 500 })]).fetch })), () => undefined, () => golden.at);
      const results = await Promise.allSettled([failing.ensureVerified(), failing.ensureVerified()]);
      expect(results.map((r) => r.status)).toEqual(["rejected", "rejected"]);
      expect((results[0] as PromiseRejectedResult).reason).toBe((results[1] as PromiseRejectedResult).reason);
    });

    it("lets a caller stop waiting without aborting the verification others need", async () => {
      let release!: () => void;
      const gate = new Promise<void>((resolve) => (release = resolve));
      const good = serving([() => new Response(golden.document)]);
      const slowGood: Fetch = async (input, init) => {
        await gate;
        return good.fetch(input, init);
      };
      const cache = new VerifiedEnclave(await Enclave.create(config({ fetch: slowGood })), () => undefined, () => golden.at);
      const controller = new AbortController();
      const impatient = cache.ensureVerified(controller.signal);
      const patient = cache.ensureVerified();
      controller.abort(new Error("impatient"));
      await expect(impatient).rejects.toThrow(/impatient/);
      release();
      expect((await patient).verification.tlsPublicKeyFP()).toBe(golden.expected.tls);
      expect(good.urls).toHaveLength(1);
    });
  });
});

describe("Enclave against a live enclave", () => {
  it.skipIf(!RUN_INTEGRATION)("verifies inference.tinfoil.sh under the embedded roots", async () => {
    const enclave = await Enclave.create({ host: "inference.tinfoil.sh", repo: "tinfoilsh/confidential-model-router" });
    const v = await enclave.verify();
    expect(v.tlsPublicKeyFP()).toMatch(/^[0-9a-f]{64}$/);
    expect(v.hpkePublicKey()).toMatch(/^[0-9a-f]{64}$/);
    expect(v.freshnessExpiresAt()!.getTime()).toBeGreaterThan(Date.now());
    const cache = new VerifiedEnclave(enclave);
    const state = await cache.ensureVerified();
    expect(cache.current()).toBe(state.verification);
  }, 120_000);
});
