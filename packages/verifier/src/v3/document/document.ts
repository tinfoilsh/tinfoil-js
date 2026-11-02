import { NotImplementedError } from "../errors.js";

/** A document's decoded hardware evidence. */
export interface CpuEvidence {
  /** Selects the platform (SEV-SNP report or TDX quote format). */
  readonly format: string;
  /** The raw SEV-SNP report or TDX quote. */
  readonly report: Uint8Array;
}

/**
 * Vendor collateral for the CPU evidence.
 * TODO(v3): flesh out with the AMD VCEK/CRL and Intel PCS shapes.
 */
export interface CpuEndorsements {
  readonly amdVcek?: unknown;
  readonly amdCrl?: unknown;
  readonly intelPcs?: unknown;
}

/** A Sigstore reference-values entry: the artifact's repo, tag, digest and bundle. */
export interface SigstoreRef {
  readonly repo: string;
  readonly tag: string;
  readonly digest: string;
  /** The raw Sigstore bundle JSON. */
  readonly bundle: Uint8Array;
}

/** A parsed v3 attestation document. */
export class Document {
  /** @internal Use {@link parse} or {@link dangerousTestOnlyDecode}. */
  constructor() {}

  cpuEvidence(): CpuEvidence {
    throw new NotImplementedError("Document.cpuEvidence");
  }

  cpuEndorsements(): CpuEndorsements {
    throw new NotImplementedError("Document.cpuEndorsements");
  }

  sigstoreCode(): SigstoreRef {
    throw new NotImplementedError("Document.sigstoreCode");
  }

  sigstorePlatform(): SigstoreRef {
    throw new NotImplementedError("Document.sigstorePlatform");
  }
}

/**
 * Strictly parses a v3 document and checks it is bound to `expectedNonce`
 * (nonce equality, endorsed-section hashes, report_data ladder).
 * Throws on any envelope failure.
 */
export function parse(docBytes: Uint8Array, expectedNonce: Uint8Array): Document {
  void docBytes;
  void expectedNonce;
  throw new NotImplementedError("document.parse");
}

/**
 * Decodes a document without checking its nonce or report_data binding, so
 * the conformance adapter can drive a single layer. Not for production use.
 */
export function dangerousTestOnlyDecode(docBytes: Uint8Array): Document {
  void docBytes;
  throw new NotImplementedError("document.dangerousTestOnlyDecode");
}
