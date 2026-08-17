// Intel TDX quote authentication against the pinned Intel SGX root,
// replaying the document's own captured PCS collateral — a 1:1 port of Go
// verifier/quote/tdx/authenticate.go. Every rejection throws
// VerificationError("QUOTE_REJECTED").

import { decodeBase64, encodeHex, utf8DecodeLenient } from "../bytes.js";
import { sgxRootCAPEM } from "../embedded/roots.js";
import {
  CollateralIntelPCSV1Format,
  endorsementCollateral,
  parseIntelPCSCollateral,
  SubjectCPU,
  type Document,
  type PCSResponse,
} from "../envelope.js";
import { VerificationError } from "../errors.js";
import { TdxGuestV2, type Measurement } from "../measurement.js";
import { pemDecode } from "../der.js";
import { parseCertificate, parseCRL, type Certificate } from "./der.js";
import { identity } from "./identity.js";
import { quoteToProtoV4, type QuoteV4, type TDQuoteBody } from "./quote.js";
import { tdxVerifyQuoteV4, type HTTPSGetter } from "./verify.js";

export interface QuoteOpts {
  rootPEM?: string;
  now?: Date;
}

// TdxQuote is a signature-verified TDX quote, not yet compared against any
// expected value.
export interface TdxQuote {
  // identity is the machines-map lookup key (PPID, lowercase hex).
  identity: string;
  // measurement carries MRTD followed by the four RTMRs.
  measurement: Measurement;
  // tcbEvaluationDataNumber is the minimum tcbEvaluationDataNumber observed
  // in the verified Intel collateral.
  tcbEvaluationDataNumber: number;
  body: TDQuoteBody;

  // The parsed quote, retained for policy validation (Go: unexported).
  quote: QuoteV4;
}

function quoteError(err: unknown): VerificationError {
  if (err instanceof VerificationError) return err;
  return new VerificationError("QUOTE_REJECTED", err instanceof Error ? err.message : String(err));
}

// tdxAuthenticate verifies the quote's signature chain up to the pinned
// Intel SGX root, replaying the document's captured PCS collateral — no
// network fetches. Callers must assemble a policy and validate before
// trusting the platform.
export async function tdxAuthenticate(doc: Document, opts?: QuoteOpts): Promise<TdxQuote> {
  const now = opts?.now ?? new Date();
  let trustedRoot: Certificate;
  try {
    trustedRoot = rootFromPEM(opts?.rootPEM ?? sgxRootCAPEM);
  } catch (err) {
    throw quoteError(err);
  }

  let quote: QuoteV4;
  try {
    let rawQuote: Uint8Array;
    try {
      rawQuote = decodeBase64(doc.cpuEvidence.reportBase64);
    } catch (err) {
      throw new Error(`decoding TDX quote: ${err instanceof Error ? err.message : String(err)}`);
    }
    try {
      quote = quoteToProtoV4(rawQuote);
    } catch (err) {
      throw new Error(`parsing TDX quote: ${err instanceof Error ? err.message : String(err)}`);
    }
    // The library parses but never constrains these: header bytes 8-11 are
    // reserved in quote v4 (exposed as QeSvn/PceSvn), and bytes past the
    // signed data are kept as extraBytes. Reserved bytes must be zero;
    // trailing bytes may only be zero padding — anything non-zero is
    // unsigned content.
    const header = quote.header;
    if (!isZero(header.qeSvn) || !isZero(header.pceSvn)) {
      throw new Error("TDX quote header carries non-zero reserved bytes");
    }
    if (!isZero(quote.extraBytes)) {
      throw new Error("TDX quote carries non-zero bytes after the signed data");
    }
  } catch (err) {
    throw quoteError(err);
  }

  // The recorder observes the tcbEvaluationDataNumber of the collateral
  // actually used, so the policy floor is enforced on verified bytes.
  const entry = endorsementCollateral(doc, CollateralIntelPCSV1Format, SubjectCPU);
  if (entry === undefined) {
    throw new VerificationError("QUOTE_REJECTED", "document carries no intel-pcs endorsement collateral for the cpu");
  }
  const data = parseIntelPCSCollateral(entry.data); // throws QUOTE_REJECTED
  let recorder: TcbEvaluationRecorder;
  try {
    recorder = new TcbEvaluationRecorder(new PCSReplayGetter(data.responses ?? [], now));
  } catch (err) {
    throw quoteError(err);
  }

  // All options explicit: collateral replayed from the document, chain
  // pinned to the Intel root, revocation checking on, validity at now.
  try {
    await tdxVerifyQuoteV4(quote, { getter: recorder, trustedRoot, now });
  } catch (err) {
    throw new VerificationError(
      "QUOTE_REJECTED",
      `verifying TDX quote: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  try {
    const id = identity(quote);
    const tcbEvaluationDataNumber = recorder.minimum();

    const body = quote.tdQuoteBody;
    const registers = [encodeHex(body.mrTd)];
    for (const rtmr of body.rtmrs) registers.push(encodeHex(rtmr));
    return {
      identity: id,
      measurement: { type: TdxGuestV2, registers },
      tcbEvaluationDataNumber,
      body,
      quote,
    };
  } catch (err) {
    throw quoteError(err);
  }
}

function isZero(b: Uint8Array): boolean {
  for (const v of b) if (v !== 0) return false;
  return true;
}

// rootFromPEM parses a single trusted root certificate (Go: pool of one).
function rootFromPEM(rootPEM: string): Certificate {
  const block = pemDecode(rootPEM);
  if (block === undefined || block.type !== "CERTIFICATE") {
    throw new Error("intel SGX root PEM carried no certificate");
  }
  return parseCertificate(block.der);
}

// pcsCollateralKey canonicalizes an Intel PCS URL for replay lookup: the
// tcbEvaluationDataNumber query parameter selects which collateral edition
// Intel serves, so a capture made at a specific number must still answer the
// library's parameterless request for the same resource.
export function pcsCollateralKey(rawURL: string): string {
  let u: URL;
  try {
    u = new URL(rawURL);
  } catch {
    // Go's url.Parse accepts nearly anything; keep unparseable keys verbatim
    // so a capture and a request canonicalize identically.
    return rawURL;
  }
  const params = [...u.searchParams.entries()].filter(([k]) => k !== "tcbEvaluationDataNumber");
  params.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)); // Go url.Values.Encode sorts by key
  u.search = params.length === 0 ? "" : "?" + params.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");
  return u.toString();
}

// canonicalMIMEHeaderKey mirrors textproto.CanonicalMIMEHeaderKey for the
// token header names PCS uses.
export function canonicalMIMEHeaderKey(key: string): string {
  if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(key)) return key;
  return key
    .split("-")
    .map((part) => (part === "" ? "" : part[0].toUpperCase() + part.slice(1).toLowerCase()))
    .join("-");
}

class PCSReplayGetter implements HTTPSGetter {
  private readonly responses = new Map<string, PCSResponse>();
  private readonly now: Date;

  constructor(responses: PCSResponse[], now: Date) {
    this.now = now;
    for (const resp of responses) {
      this.responses.set(pcsCollateralKey(resp.url).toLowerCase(), resp);
    }
  }

  get(requestURL: string): { headers: Map<string, string[]>; body: Uint8Array } {
    const key = pcsCollateralKey(requestURL).toLowerCase();
    const resp = this.responses.get(key);
    if (resp === undefined) {
      throw new Error(`intel-pcs collateral has no captured response for ${requestURL}`);
    }
    let body: Uint8Array;
    try {
      body = decodeBase64(resp.bodyBase64);
    } catch (err) {
      throw new Error(`decoding captured PCS response body for ${requestURL}: ${err instanceof Error ? err.message : String(err)}`);
    }
    // The library checks CRL NextUpdate but not ThisUpdate, so a future-dated
    // capture would otherwise pass. Intel also serves a root-CA CRL from a
    // .der URL that does not identify the body as a CRL.
    let isCRL = false;
    try {
      const crl = parseCRL(body);
      isCRL = true;
      const t = this.now.getTime();
      if (t < crl.thisUpdate.getTime() || t > crl.nextUpdate.getTime()) {
        throw new Error(`captured CRL for ${requestURL} is outside its validity window`);
      }
    } catch (err) {
      if (isCRL) throw err;
      if (key.includes("crl")) {
        throw new Error(`parsing captured CRL for ${requestURL}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    // Header keys are matched verbatim (canonical MIME form), so normalize
    // whatever casing the capture used.
    const headers = new Map<string, string[]>();
    for (const [k, v] of resp.headers ?? new Map<string, string[]>()) {
      headers.set(canonicalMIMEHeaderKey(k), v ?? []);
    }
    return { headers, body };
  }
}

// TcbEvaluationRecorder observes the tcbEvaluationDataNumber carried by the
// TCB Info and QE Identity responses that quote verification consumes.
class TcbEvaluationRecorder implements HTTPSGetter {
  private readonly inner: HTTPSGetter;
  private tcbInfo?: number;
  private qeIdentity?: number;

  constructor(inner: HTTPSGetter) {
    this.inner = inner;
  }

  get(requestURL: string): { headers: Map<string, string[]>; body: Uint8Array } {
    const result = this.inner.get(requestURL);

    // Parse failures below are ignored on purpose: these bytes are
    // authenticated and interpreted by the verification core, and this
    // wrapper only observes one field. A response that never parses leaves
    // its slot unset, which fails minimum() after verification.
    let path: string;
    try {
      path = new URL(requestURL).pathname;
    } catch {
      return result;
    }
    try {
      const parsed = JSON.parse(utf8DecodeLenient(result.body)) as Record<string, unknown>;
      if (path.endsWith("/tcb")) {
        const n = (parsed?.tcbInfo as Record<string, unknown> | undefined)?.tcbEvaluationDataNumber;
        if (typeof n === "number" && Number.isInteger(n)) this.tcbInfo = n;
      } else if (path.endsWith("/qe/identity")) {
        const n = (parsed?.enclaveIdentity as Record<string, unknown> | undefined)?.tcbEvaluationDataNumber;
        if (typeof n === "number" && Number.isInteger(n)) this.qeIdentity = n;
      }
    } catch {
      // observed nothing
    }
    return result;
  }

  // minimum returns the lower of the two observed numbers; both responses
  // must have been seen (quote verification always fetches both on success).
  minimum(): number {
    if (this.tcbInfo === undefined || this.qeIdentity === undefined) {
      throw new Error("collateral tcbEvaluationDataNumber was not observed during quote verification");
    }
    return this.qeIdentity < this.tcbInfo ? this.qeIdentity : this.tcbInfo;
  }
}
