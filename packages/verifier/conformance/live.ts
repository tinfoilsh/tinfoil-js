/**
 * The integration lane: fetch a live enclave's attestation document with a
 * fresh nonce, verify it through the package's public entry with the embedded
 * production roots and the current time, bind the TLS channel to the
 * endorsed key, and report the facts. Test tooling: Node APIs are fine here.
 */
import { connect } from "node:tls";
import { NONCE_SIZE, randomNonce, Verifier, type Verification } from "../src/v3/index.js";
import { VERIFIER_NAME, VERIFIER_VERSION } from "../src/version.js";
import { certPubkeyFP } from "../src/v3/index.js";
import { ExitCode, expectedOf, measurementOf, rejectionCode, type Output, type Result } from "./adapter.js";

export const STAGE_LIVE = "live-verify";

const ATTESTATION_ENDPOINT = "/.well-known/tinfoil-attestation";
const SDK_NAME_HEADER = "Tinfoil-SDK";
const SDK_VERSION_HEADER = "Tinfoil-SDK-Version";
const FETCH_TIMEOUT_MS = 30_000;
const MAX_ATTESTATION_BYTES = 32 << 20;
const MAX_REDIRECTS = 10;
/** Back-off between attempts when the service rate-limits (HTTP 429), in milliseconds. */
const RETRY_DELAYS_MS = [2_000, 4_000, 8_000];

/** The stdin JSON of the lane: the enclave host (optionally with a port) and the repository pin. */
export interface LiveRequest {
  readonly host: string;
  readonly repo: string;
}

export function decodeLiveRequest(raw: unknown): LiveRequest | undefined {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return undefined;
  const o = raw as Record<string, unknown>;
  if (typeof o.host !== "string" || typeof o.repo !== "string" || o.host === "" || o.repo === "") return undefined;
  return { host: o.host, repo: o.repo };
}

/** Runs the lane; a thrown error is an internal failure (exit 1), a rejection is reported in the output. */
export async function liveVerify(req: LiveRequest, log: (line: string) => void = () => {}): Promise<Result> {
  const verifier = await Verifier.create();
  const nonce = randomNonce();
  const doc = await fetchDocument(req.host, nonce, log);

  let verified: Verification;
  try {
    verified = await verifier.verifyV3(doc, nonce, req.repo);
  } catch (err) {
    log(`live verification: ${err instanceof Error ? err.message : String(err)}`);
    const mapped = rejectionCode(err);
    if (mapped === undefined) throw err;
    return { output: { stage: STAGE_LIVE, accepted: false, rejection: { code: mapped.code } }, exitCode: mapped.exitCode };
  }
  const tlsFP = verified.tlsPublicKeyFP();
  const hpke = verified.hpkePublicKey();
  if (tlsFP === undefined || hpke === undefined) {
    log("endorsed keys: the document endorses no TLS fingerprint or no HPKE key in the expected formats");
    return reject("ENVELOPE_REJECTED");
  }

  // Channel binding: the endorsed TLS key must be the key the live enclave presents on the wire.
  const live = await tlsSpkiFingerprint(req.host);
  if (live !== tlsFP) {
    log(`channel binding: live TLS key ${live} != endorsed ${tlsFP}`);
    return reject("POLICY_REJECTED");
  }
  const output: Output = {
    stage: STAGE_LIVE,
    accepted: true,
    outputs: {
      code_digest: verified.codeDigest(),
      code_measurement: expectedOf(verified.codeMeasurement()),
      enclave_measurement: measurementOf(verified.enclaveMeasurement()),
      tls_public_key_fp: tlsFP,
      hpke_public_key: hpke,
      channel_binding: "tls-spki",
    },
  };
  return { output, exitCode: ExitCode.Accepted };
}

function reject(code: "ENVELOPE_REJECTED" | "POLICY_REJECTED"): Result {
  return { output: { stage: STAGE_LIVE, accepted: false, rejection: { code } }, exitCode: ExitCode.Rejected };
}

/**
 * GET https://<host>/.well-known/tinfoil-attestation?nonce=<hex>, following
 * at most ten HTTPS redirects, with the SDK headers, a 30 s timeout and a
 * 32 MiB cap. A 429 is retried a few times with back-off.
 */
export async function fetchDocument(host: string, nonce: Uint8Array, log: (line: string) => void): Promise<Uint8Array> {
  if (nonce.length !== NONCE_SIZE) throw new Error(`nonce must be ${NONCE_SIZE} bytes`);
  if (!isAuthority(host)) throw new Error(`invalid host ${JSON.stringify(host)}: want a host with an optional port`);
  const hex = Array.from(nonce, (b) => b.toString(16).padStart(2, "0")).join("");
  const start = `https://${host}${ATTESTATION_ENDPOINT}?nonce=${hex}`;
  for (let attempt = 0; ; attempt++) {
    const response = await getFollowingRedirects(start);
    if (response.status === 429 && attempt < RETRY_DELAYS_MS.length) {
      await response.body?.cancel();
      log(`HTTP 429 from ${host}; retrying in ${RETRY_DELAYS_MS[attempt] / 1000}s`);
      await new Promise((resolve) => setTimeout(resolve, RETRY_DELAYS_MS[attempt]));
      continue;
    }
    if (response.status > 299) throw new Error(`HTTP GET ${start}: ${response.status} ${response.statusText}`);
    const body = new Uint8Array(await response.arrayBuffer());
    if (body.length > MAX_ATTESTATION_BYTES) throw new Error(`attestation document exceeds ${MAX_ATTESTATION_BYTES} bytes`);
    return body;
  }
}

async function getFollowingRedirects(url: string): Promise<Response> {
  let target = url;
  for (let hops = 0; ; hops++) {
    const response = await fetch(target, {
      method: "GET",
      redirect: "manual",
      headers: { [SDK_NAME_HEADER]: VERIFIER_NAME, [SDK_VERSION_HEADER]: VERIFIER_VERSION },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (response.status < 300 || response.status > 399) return response;
    await response.body?.cancel();
    const location = response.headers.get("location");
    if (location === null) throw new Error(`HTTP GET ${target}: ${response.status} without a Location header`);
    const next = new URL(location, target);
    if (next.protocol !== "https:") throw new Error(`refusing redirect to non-HTTPS URL ${next.href}`);
    if (hops >= MAX_REDIRECTS) throw new Error("stopped after 10 redirects");
    target = next.href;
  }
}

/** Whether `s` is exactly the host (with optional port) of an HTTPS URL. */
function isAuthority(s: string): boolean {
  try {
    const u = new URL(`https://${s}`);
    return u.host === s && u.pathname === "/" && u.username === "" && u.password === "" && u.search === "" && u.hash === "";
  } catch {
    return false;
  }
}

/** The SPKI SHA-256 fingerprint of the leaf certificate `host` presents on a fresh TLS connection. */
export function tlsSpkiFingerprint(host: string): Promise<string> {
  const u = new URL(`https://${host}`);
  const port = u.port === "" ? 443 : Number(u.port);
  const serverName = u.hostname;
  return new Promise((resolve, reject) => {
    const socket = connect({ host: serverName, port, servername: serverName, rejectUnauthorized: false, timeout: 10_000 }, () => {
      const peer = socket.getPeerCertificate();
      socket.end();
      if (peer === undefined || peer.raw === undefined) {
        reject(new Error("no peer certificates"));
        return;
      }
      certPubkeyFP(new Uint8Array(peer.raw)).then(resolve, reject);
    });
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error(`dialing ${host}: timeout`));
    });
    socket.on("error", reject);
  });
}
