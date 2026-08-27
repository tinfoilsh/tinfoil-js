// Node-only live-verify integration lane (spec §7): verify a live enclave
// through the SDK's public production entry point — verifyDocumentV3 with no
// opts (embedded roots, current time), never the adapter's composed flow —
// then assert the live connection's SPKI fingerprint equals the endorsed one
// (Go: cmd/tinfoil-conformance/live.go).

import { createHash } from "node:crypto";
import * as tls from "node:tls";
import {
  fetchAttestation,
  hpkePublicKey,
  randomNonce,
  tlsPublicKeyFP,
  VerificationError,
  verifyDocumentV3,
  type VerifiedDocumentV3,
} from "@tinfoilsh/verifier";
import { ExitAccepted, ExitInternal, ExitMalformed, ExitRejected, type Output } from "./run.js";

const StageLive = "live-verify";

interface LiveRequest {
  host?: string;
  repo?: string;
}

export interface LiveResult {
  output?: Output; // absent on internal (non-verdict) errors
  exitCode: number;
}

function rejectLive(code: string): LiveResult {
  return { output: { stage: StageLive, accepted: false, rejection: { code } }, exitCode: ExitRejected };
}

// runLive executes the live-verify lane on a {"host","repo"} request
// (Go: cmd runLive).
export async function runLive(reqJSON: string): Promise<LiveResult> {
  let req: LiveRequest;
  try {
    req = JSON.parse(reqJSON) as LiveRequest;
  } catch {
    req = {};
  }
  if (!req.host || !req.repo) {
    return {
      output: { stage: StageLive, accepted: false, rejection: { code: "MALFORMED_INPUT" } },
      exitCode: ExitMalformed,
    };
  }

  const nonce = randomNonce();
  let doc: Uint8Array;
  try {
    doc = await fetchAttestation(req.host, nonce); // public path (Go: envelope.Fetch)
  } catch (err) {
    process.stderr.write(`fetching attestation from ${req.host}: ${message(err)}\n`);
    return { exitCode: ExitInternal };
  }

  let verified: VerifiedDocumentV3;
  try {
    verified = await verifyDocumentV3(doc, nonce, req.repo); // public path: embedded roots, current time
  } catch (err) {
    process.stderr.write(`live verification: ${message(err)}\n`);
    if (err instanceof VerificationError) return rejectLive(err.layer);
    throw err;
  }

  let tlsFP: string;
  let hpke: string;
  try {
    tlsFP = tlsPublicKeyFP(verified);
    hpke = hpkePublicKey(verified);
  } catch (err) {
    process.stderr.write(`endorsed keys: ${message(err)}\n`);
    return rejectLive("ENVELOPE_REJECTED");
  }

  // Channel binding: the endorsed TLS key must be the key the live enclave
  // actually presents on the wire.
  let live: string;
  try {
    live = await tlsSPKIFingerprint(req.host);
  } catch (err) {
    process.stderr.write(`dialing ${req.host} for channel binding: ${message(err)}\n`);
    return { exitCode: ExitInternal };
  }
  if (live !== tlsFP) {
    process.stderr.write(`channel binding: live TLS key ${live} != endorsed ${tlsFP}\n`);
    return rejectLive("POLICY_REJECTED");
  }

  return {
    output: {
      stage: StageLive,
      accepted: true,
      outputs: {
        code_digest: verified.codeDigest,
        code_measurement: { type: verified.codeMeasurement.type, registers: verified.codeMeasurement.registers },
        enclave_measurement: {
          type: verified.enclaveMeasurement.type,
          registers: verified.enclaveMeasurement.registers,
        },
        tls_public_key_fp: tlsFP,
        hpke_public_key: hpke,
        channel_binding: "tls-spki",
      },
    },
    exitCode: ExitAccepted,
  };
}

// tlsSPKIFingerprint dials host:443 and returns the SHA-256 hex fingerprint of
// the presented leaf's SPKI DER — the same computation Go's ConnectionCertFP
// performs. Chain verification is skipped on purpose: trust comes from
// matching the attested fingerprint, not the public PKI.
function tlsSPKIFingerprint(host: string): Promise<string> {
  const { name, port } = splitHostPort(host); // host may already carry a port
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host: name, port, servername: name, rejectUnauthorized: false, timeout: 10_000 },
      () => {
        try {
          const cert = socket.getPeerX509Certificate();
          if (cert === undefined) throw new Error("no peer certificate");
          const spki = cert.publicKey.export({ type: "spki", format: "der" });
          resolve(createHash("sha256").update(spki).digest("hex"));
        } catch (err) {
          reject(err instanceof Error ? err : new Error(String(err)));
        } finally {
          socket.destroy();
        }
      },
    );
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error("TLS dial timed out"));
    });
    socket.on("error", (err) => {
      socket.destroy();
      reject(err);
    });
  });
}

function splitHostPort(host: string): { name: string; port: number } {
  const i = host.lastIndexOf(":");
  if (i !== -1 && /^\d+$/.test(host.slice(i + 1))) {
    return { name: host.slice(0, i), port: Number(host.slice(i + 1)) };
  }
  return { name: host, port: 443 };
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
