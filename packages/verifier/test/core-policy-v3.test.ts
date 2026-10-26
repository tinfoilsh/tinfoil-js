import { afterEach, describe, expect, it, vi } from "vitest";
import { createVerifierForConformance, Verifier } from "../src/client.js";
import { parseJSON, unbase64, unhex, utf8 } from "../src/encoding.js";
import { KEY_TLS, KEY_HPKE } from "../src/document.js";
import type { UntrustedConfig, VerifierOptions } from "../src/types.js";
import embeddedFixture from "./fixtures/registry-v3/snp-golden-all-embedded.json";
import signedFixture from "./fixtures/registry-v3/snp-golden.json";
import capture from "./fixtures/production-v3.json";

function trust(input: typeof signedFixture.input) {
  return {
    sigstoreRoot: parseJSON(unbase64(input.sigstore_trusted_root_json_b64)),
    amdRootPem: input.amd_root_ca_pem,
  };
}
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}
afterEach(() => vi.unstubAllGlobals());

describe("immutable caller policy and verification time", () => {
  it("detaches every embedded reference component at construction", async () => {
    const input = embeddedFixture.input;
    const e = input.verifier_options.embedded_references;
    const embedded = {
      config: { bytes: unbase64(e.config.bytes_b64), name: e.config.name },
      runtime: unbase64(e.runtime_b64),
      platform: unbase64(e.platform_b64),
    };
    const verifier = createVerifierForConformance(
      { embeddedReferences: embedded },
      trust(input as any),
    );
    embedded.config.bytes.fill(0);
    embedded.config.name = "/wrong/service/rev2";
    embedded.runtime.fill(0);
    embedded.platform.fill(0);
    const result = await verifier.verifyDocumentV3At(
      unbase64(input.document_b64),
      unhex(input.nonce_hex),
      input.repo,
      new Date(input.verification_time_unix * 1000),
    );
    expect(result.config?.digest).toBe(embeddedFixture.expected.config.digest);
    expect(result.config?.name).toBe(embeddedFixture.expected.config.name);
    expect(result.runtime?.digest).toBe(
      embeddedFixture.expected.runtime.digest,
    );
    expect(result.platform?.digest).toBe(
      embeddedFixture.expected.platform.digest,
    );
    expect(result.freshnessExpiresAt).toBeUndefined();
  });

  it("invokes concurrent authorizers with detached material and isolates their decisions", async () => {
    const input = signedFixture.input;
    const bothEntered = deferred(),
      release = deferred();
    const observed: UntrustedConfig[] = [];
    const options: VerifierOptions = {
      freshnessSigningKeys:
        input.verifier_options.freshness_signing_keys_b64.map(unbase64),
      configAuthorizer: async (material) => {
        const index = observed.push(material);
        if (index === 2) bothEntered.resolve();
        await release.promise;
        material.config.fill(0);
        (material.bundle as any).dsseEnvelope.payload = "invalid";
        if (index === 2) throw new Error("independent denial");
      },
    };
    const verifier = createVerifierForConformance(options, trust(input));
    const verify = () =>
      verifier.verifyDocumentV3At(
        unbase64(input.document_b64),
        unhex(input.nonce_hex),
        "",
        new Date(input.verification_time_unix * 1000),
      );
    const pending = Promise.allSettled([verify(), verify()]);
    await bothEntered.promise;
    expect(observed[0].config).not.toBe(observed[1].config);
    expect(observed[0].bundle).not.toBe(observed[1].bundle);
    release.resolve();
    const results = await pending;
    expect(results.map((result) => result.status).sort()).toEqual([
      "fulfilled",
      "rejected",
    ]);
    const accepted = results.find((result) => result.status === "fulfilled")!;
    const rejected = results.find((result) => result.status === "rejected")!;
    if (accepted.status === "fulfilled")
      expect(accepted.value.config?.digest).toBe(
        signedFixture.expected.config.digest,
      );
    if (rejected.status === "rejected")
      expect(rejected.reason).toMatchObject({
        layer: "provenance",
        message: "Caller policy rejected config",
      });
  });

  it("suppresses only the trust step replaced by an embedded runtime or platform", async () => {
    const input = signedFixture.input;
    const remote = parseJSON(unbase64(input.document_b64));
    for (const component of ["runtime", "platform"] as const) {
      const embedded =
        component === "runtime"
          ? {
              runtime: unbase64(
                remote.collateral.find((e: any) => e.id === "runtime").data
                  .manifest_base64,
              ),
            }
          : {
              platform: unbase64(
                embeddedFixture.input.verifier_options.embedded_references
                  .platform_b64,
              ),
            };
      const verifier = createVerifierForConformance(
        {
          embeddedReferences: embedded,
          configSigningKeys:
            input.verifier_options.config_signing_keys_b64.map(unbase64),
          freshnessSigningKeys:
            input.verifier_options.freshness_signing_keys_b64.map(unbase64),
        },
        trust(input),
      );
      const doc = structuredClone(remote);
      doc.collateral = doc.collateral.filter(
        (e: any) => ![component, component + "-freshness"].includes(e.id),
      );
      const verify = () =>
        verifier.verifyDocumentV3At(
          utf8(JSON.stringify(doc)),
          unhex(input.nonce_hex),
          input.repo,
          new Date(input.verification_time_unix * 1000),
        );
      const result = await verify();
      expect(result[component]?.source).toBe("embedded");
      expect(result.config?.source).toBe("endorsement");
      const other = component === "runtime" ? "platform" : "runtime";
      expect(result[other]?.source).toBe("endorsement");
      doc.collateral = doc.collateral.filter(
        (e: any) => e.id !== other + "-freshness",
      );
      await expect(verify()).rejects.toMatchObject({ layer: "provenance" });
    }
  });

  it("samples the live clock exactly once for a complete production verification", async () => {
    const verifier = new Verifier();
    const OriginalDate = Date;
    let reads = 0;
    const now = new OriginalDate(capture.capturedAt).getTime();
    class CountingDate extends OriginalDate {
      constructor(value?: string | number | Date) {
        if (arguments.length === 0) {
          super(now);
          reads++;
        } else super(value as string);
      }
      static now() {
        reads++;
        return now;
      }
    }
    vi.stubGlobal("Date", CountingDate);
    const result = await verifier.verifyDocumentV3(
      unbase64(capture.documentBase64),
      unhex(capture.nonceHex),
      capture.identity,
    );
    expect(result.metadata.verifiedAt.getTime()).toBe(now);
    expect(reads).toBe(1);
    expect(result.cryptoMaterialData("tls", KEY_TLS)).toBe(
      result.tlsPublicKeyFingerprint(),
    );
    expect(result.cryptoMaterialData("tls", KEY_HPKE)).toBeUndefined();
    expect(result.cryptoMaterialData("missing", KEY_TLS)).toBeUndefined();
  });
});

it("enforces a zero-age policy at the approval instant and rejects one millisecond later", async () => {
  const input = signedFixture.input;
  const verifier = createVerifierForConformance({
    freshnessMaxAgeMs: 0,
    configSigningKeys: input.verifier_options.config_signing_keys_b64.map(unbase64),
    freshnessSigningKeys: input.verifier_options.freshness_signing_keys_b64.map(unbase64),
  }, trust(input));
  expect(verifier.freshnessMaxAgeMs).toBe(0);
  const now = input.verification_time_unix * 1000;
  const verify = (at: number) => verifier.verifyDocumentV3At(unbase64(input.document_b64), unhex(input.nonce_hex), input.repo, new Date(at));
  const result = await verify(now);
  expect(result.freshnessExpiresAt?.getTime()).toBe(now);
  await expect(verify(now + 1)).rejects.toMatchObject({ layer: "provenance" });
});
