import { describe, it, expect } from "vitest";
import { X509Certificate } from "@freedomofpress/sigstore-browser";

const RUN_INTEGRATION = process.env.RUN_TINFOIL_INTEGRATION === "true";

describe("ATC API", () => {
  describe("fetchAttestationBundle", () => {
    it.skipIf(!RUN_INTEGRATION)("should fetch a complete attestation bundle from production ATC", async () => {
      const { fetchAttestationBundle } = await import("../src/atc");

      const bundle = await fetchAttestationBundle();

      // Verify bundle structure
      expect(bundle).toBeDefined();
      expect(bundle.domain).toBeDefined();
      expect(typeof bundle.domain).toBe("string");
      expect(bundle.domain).toMatch(/\.tinfoil\.sh$/);

      // Verify enclave attestation report
      expect(bundle.enclaveAttestationReport).toBeDefined();
      expect(bundle.enclaveAttestationReport.format).toBe("https://tinfoil.sh/predicate/sev-snp-guest/v2");
      expect(bundle.enclaveAttestationReport.body).toBeDefined();
      expect(typeof bundle.enclaveAttestationReport.body).toBe("string");

      // Verify digest
      expect(bundle.digest).toBeDefined();
      expect(typeof bundle.digest).toBe("string");
      expect(bundle.digest).toMatch(/^[a-f0-9]{64}$/); // SHA256 hex

      // Verify sigstore bundle structure using @freedomofpress/sigstore-browser
      const sigstoreBundle = bundle.sigstoreBundle as any;
      expect(sigstoreBundle).toBeDefined();
      expect(sigstoreBundle.mediaType).toMatch(/^application\/vnd\.dev\.sigstore\.bundle\.v\d+\.\d+\+json$/);

      // Verify verificationMaterial structure
      expect(sigstoreBundle.verificationMaterial).toBeDefined();
      expect(sigstoreBundle.verificationMaterial.tlogEntries).toBeDefined();
      expect(Array.isArray(sigstoreBundle.verificationMaterial.tlogEntries)).toBe(true);
      expect(sigstoreBundle.verificationMaterial.tlogEntries.length).toBeGreaterThan(0);

      // Verify tlog entry structure
      const tlogEntry = sigstoreBundle.verificationMaterial.tlogEntries[0];
      expect(tlogEntry.logIndex).toBeDefined();
      expect(tlogEntry.logId?.keyId).toBeDefined();
      expect(tlogEntry.kindVersion?.kind).toBe("dsse");
      expect(tlogEntry.integratedTime).toBeDefined();
      expect(tlogEntry.inclusionProof).toBeDefined();

      // Verify certificate can be parsed using sigstore library
      expect(sigstoreBundle.verificationMaterial.certificate).toBeDefined();
      expect(sigstoreBundle.verificationMaterial.certificate.rawBytes).toBeDefined();
      const certDer = Uint8Array.from(atob(sigstoreBundle.verificationMaterial.certificate.rawBytes), c => c.charCodeAt(0));
      const cert = X509Certificate.parse(certDer);
      expect(cert.version).toBe("v3");
      expect(cert.subjectDN).toBeDefined();

      // Verify DSSE envelope structure
      expect(sigstoreBundle.dsseEnvelope).toBeDefined();
      expect(sigstoreBundle.dsseEnvelope.payloadType).toBe("application/vnd.in-toto+json");
      expect(sigstoreBundle.dsseEnvelope.payload).toBeDefined();
      expect(sigstoreBundle.dsseEnvelope.signatures).toBeDefined();
      expect(Array.isArray(sigstoreBundle.dsseEnvelope.signatures)).toBe(true);
      expect(sigstoreBundle.dsseEnvelope.signatures.length).toBeGreaterThan(0);
      expect(sigstoreBundle.dsseEnvelope.signatures[0].sig).toBeDefined();

      // Decode and verify in-toto payload structure
      const payloadJson = JSON.parse(atob(sigstoreBundle.dsseEnvelope.payload));
      expect(payloadJson._type).toBe("https://in-toto.io/Statement/v1");
      expect(payloadJson.subject).toBeDefined();
      expect(Array.isArray(payloadJson.subject)).toBe(true);
      expect(payloadJson.subject[0].digest?.sha256).toBeDefined();
      expect(payloadJson.predicateType).toContain("tinfoil.sh/predicate/");
      expect(payloadJson.predicate).toBeDefined();

      // Verify VCEK (base64-encoded DER)
      expect(bundle.vcek).toBeDefined();
      expect(typeof bundle.vcek).toBe("string");
      expect(bundle.vcek.length).toBeGreaterThan(100); // VCEK should be substantial
    });

    it.skipIf(!RUN_INTEGRATION)("should accept custom ATC URL", async () => {
      const { fetchAttestationBundle } = await import("../src/atc");

      // Using production URL explicitly to test custom URL parameter
      const bundle = await fetchAttestationBundle("https://atc.tinfoil.sh");

      expect(bundle).toBeDefined();
      expect(bundle.domain).toBeDefined();
    });

    it("should throw on invalid ATC URL", async () => {
      const { fetchAttestationBundle } = await import("../src/atc");

      await expect(fetchAttestationBundle("https://invalid.example.com")).rejects.toThrow();
    });
  });

  describe("fetchRouter", () => {
    it.skipIf(!RUN_INTEGRATION)("should fetch a router address from production ATC", async () => {
      const { fetchRouter } = await import("../src/atc");

      const router = await fetchRouter();

      expect(router).toBeDefined();
      expect(typeof router).toBe("string");
      expect(router).toMatch(/\.tinfoil\.sh$/);
    });

    it.skipIf(!RUN_INTEGRATION)("should accept custom ATC URL", async () => {
      const { fetchRouter } = await import("../src/atc");

      // Using production URL explicitly to test custom URL parameter
      const router = await fetchRouter("https://atc.tinfoil.sh");

      expect(router).toBeDefined();
      expect(typeof router).toBe("string");
    });

    it("should throw on invalid ATC URL", async () => {
      const { fetchRouter } = await import("../src/atc");

      await expect(fetchRouter("https://invalid.example.com")).rejects.toThrow();
    });
  });
});
