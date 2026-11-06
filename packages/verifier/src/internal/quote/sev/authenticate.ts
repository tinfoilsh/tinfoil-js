/**
 * AMD SEV-SNP report authentication: the report's signature chain from the
 * VCEK through the product's signing key to the pinned AMD root, with the
 * VCEK checked against the document-carried revocation list. Nothing here
 * compares the report against a policy; that is the expectations module.
 */
import type { SevSnpMeasurement } from "../../../measurement.js";
import { AMD_GENOA_CERT_CHAIN_PEM } from "../../../trust/amd-genoa-chain.js";
import { AMD_TURIN_CERT_CHAIN_PEM } from "../../../trust/amd-turin-chain.js";
import { parseCertificate, X509Error, type Certificate } from "../../x509/certificate.js";
import { isRevoked, parseRevocationList, verifyRevocationList } from "../../x509/crl.js";
import { DerError } from "../../x509/der.js";
import { identity } from "./identity.js";
import {
  parseReport,
  PRODUCT_GENOA,
  PRODUCT_TURIN,
  productLine,
  SIGNATURE_ALGO_ECDSA_P384_SHA384,
  SIGNER_VCEK,
  signatureRaw,
  signedBytes,
  type ProductLine,
  type SevReport,
} from "./report.js";
import { checkCertChainShape, checkVcekShape, parseAmdRoots, verifyVcekChain, type AmdRoots, type VcekExtensions } from "./vcek.js";

export { PRODUCT_GENOA, PRODUCT_TURIN, REPORT_SIZE, parseReport, productLine, type ProductLine, type SevReport } from "./report.js";
export { assembleSev, validateSev, type SevExpectations } from "./expectations.js";

export interface SevOptions {
  /** PEM chain (ASK then ARK) replacing the embedded one for the report's product. Test-only. */
  readonly dangerousTestOnlyRoot?: Uint8Array;
}

/** The inputs an SEV-SNP quote needs: the raw report and its collateral. */
export interface SevEvidence {
  readonly report: Uint8Array;
  readonly vcekDer: Uint8Array;
  /** ASK then ARK. */
  readonly certChainPem: string;
  readonly crlDer: Uint8Array;
}

/** An authenticated report. */
export interface SevQuote {
  /** CHIP_ID, lowercase hex. */
  readonly identity: string;
  readonly measurement: SevSnpMeasurement;
  readonly report: SevReport;
  readonly productLine: ProductLine;
  /** What the VCEK that signed the report is endorsed for. */
  readonly vcek: VcekExtensions;
}

const message = (err: unknown): string => (err instanceof Error ? err.message : String(err));

/** The pinned ASK and ARK for a product line, or the injected replacement. */
function trustedRoots(product: ProductLine, override: Uint8Array | undefined): AmdRoots {
  let pem: string;
  if (override !== undefined) {
    pem = new TextDecoder().decode(override);
  } else {
    switch (product) {
      case PRODUCT_GENOA:
        pem = AMD_GENOA_CERT_CHAIN_PEM;
        break;
      case PRODUCT_TURIN:
        pem = AMD_TURIN_CERT_CHAIN_PEM;
        break;
    }
  }
  try {
    return parseAmdRoots(pem);
  } catch (err) {
    throw new Error(`parsing AMD ${product} root certificates: ${message(err)}`);
  }
}

async function verifyReportSignature(reportBytes: Uint8Array, report: SevReport, vcek: Certificate): Promise<void> {
  if (report.signatureAlgo !== SIGNATURE_ALGO_ECDSA_P384_SHA384) throw new Error(`unknown SignatureAlgo: ${report.signatureAlgo}`);
  const raw = signatureRaw(report);
  let ok = false;
  try {
    const key = await crypto.subtle.importKey("spki", vcek.spki as Uint8Array<ArrayBuffer>, { name: "ECDSA", namedCurve: "P-384" }, false, ["verify"]);
    ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-384" }, key, raw as Uint8Array<ArrayBuffer>, signedBytes(reportBytes) as Uint8Array<ArrayBuffer>);
  } catch {
    ok = false;
  }
  if (!ok) throw new Error("report signature verification error: signature does not verify under the VCEK");
}

/**
 * Authenticates a report at `now`: the VCEK and CRL are present and the
 * ASK+ARK chain well formed; the CRL is current; the report parses and names
 * a supported product; the VCEK has the KDS shape for that product and
 * chains to the pinned (or injected) roots; the CRL is the product root's and
 * revokes neither the signing key nor the VCEK; the report is VCEK-signed and
 * its signature verifies; CHIP_ID is not masked.
 */
export async function authenticateSev(evidence: SevEvidence, now: Date, opts?: SevOptions): Promise<SevQuote> {
  if (Number.isNaN(now.getTime())) throw new Error("verification time is required");
  if (evidence.vcekDer.length === 0) throw new Error("amd-vcek collateral carries an empty VCEK");
  try {
    checkCertChainShape(evidence.certChainPem);
  } catch (err) {
    throw new Error(`amd-vcek collateral: ${message(err)}`);
  }
  if (evidence.crlDer.length === 0) throw new Error("amd-crl collateral carries an empty CRL");
  let crl;
  try {
    crl = parseRevocationList(evidence.crlDer);
  } catch (err) {
    throw new Error(`parsing amd-crl collateral: ${message(err)}`);
  }
  const t = now.getTime();
  if (t < crl.thisUpdate.getTime() || t > crl.nextUpdate.getTime()) {
    throw new Error(
      `amd-crl collateral is outside its validity window (this_update ${crl.thisUpdate.toISOString()}, next_update ${crl.nextUpdate.toISOString()})`,
    );
  }

  let report: SevReport;
  try {
    report = parseReport(evidence.report);
  } catch (err) {
    throw new Error(`failed to parse report: ${message(err)}`);
  }
  const product = productLine(report);
  const roots = trustedRoots(product, opts?.dangerousTestOnlyRoot);
  if (report.signer.signingKey !== SIGNER_VCEK) throw new Error("report is not VCEK-signed; only VCEK-signed reports are supported");

  let vcek: Certificate;
  try {
    vcek = parseCertificate(evidence.vcekDer);
  } catch (err) {
    if (err instanceof X509Error || err instanceof DerError) throw new Error(`could not interpret VCEK DER bytes: ${err.message}`);
    throw err;
  }
  const exts = checkVcekShape(vcek, product);
  await verifyVcekChain(vcek, roots, now);

  try {
    await verifyRevocationList(crl, roots.ark, now);
  } catch (err) {
    throw new Error(`CRL is not the ${product} root's: ${message(err)}`);
  }
  if (isRevoked(crl, roots.ask.serialNumber)) throw new Error("ASK was revoked");
  if (isRevoked(crl, vcek.serialNumber)) throw new Error("VCEK was revoked");

  await verifyReportSignature(evidence.report, report, vcek);

  if (report.signer.maskChipKey) throw new Error("report masks CHIP_ID; masked platform identities are unsupported");
  return {
    identity: identity(report.chipId),
    measurement: { platform: "sev-snp", launch: report.measurement.slice() },
    report,
    productLine: product,
    vcek: exts,
  };
}
