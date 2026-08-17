// PPID extraction from a verified TDX quote's PCK leaf certificate, a 1:1
// port of Go verifier/quote/tdx/identity.go. The PPID is authenticated
// because the PCK chain is validated up to the Intel SGX root during quote
// verification; callers must only invoke this after verification succeeds.

import { decodeHex, encodeHex } from "../bytes.js";
import { bytesToLatin1, parseCertificate, pemDecode, type Certificate } from "./der.js";
import { pckCertificateExtensions } from "./pcs.js";
import type { QuoteV4 } from "./quote.js";

// identity extracts the machines-map lookup key (the 16-byte PPID, lowercase
// hex) from the PCK leaf certificate embedded in the quote.
export function identity(quote: QuoteV4): string {
  const leaf = pckLeafCertificate(quote);
  let ppidHex: string;
  try {
    ppidHex = pckCertificateExtensions(leaf).ppid;
  } catch (err) {
    throw new Error(`parsing PCK certificate extensions: ${err instanceof Error ? err.message : String(err)}`);
  }
  let ppid: Uint8Array;
  try {
    ppid = decodeHex(ppidHex);
  } catch {
    ppid = new Uint8Array(0);
  }
  if (ppid.length !== 16) {
    throw new Error(`PCK certificate carries malformed PPID ${JSON.stringify(ppidHex)}`);
  }
  // Re-encode rather than returning the parsed string: the machines-map
  // lookup is case-sensitive and this guarantees canonical lowercase hex.
  return encodeHex(ppid);
}

function pckLeafCertificate(quote: QuoteV4): Certificate {
  const chainData = quote.signedData.certificationData.qeReportCertificationData.pckCertificateChainData;
  if (chainData.pckCertChain.length === 0) {
    throw new Error("quote carries no PCK certificate chain (certification data type 5)");
  }
  const block = pemDecode(bytesToLatin1(chainData.pckCertChain));
  if (block === undefined || block.type !== "CERTIFICATE") {
    throw new Error("PCK certificate chain is not PEM");
  }
  try {
    return parseCertificate(block.der);
  } catch (err) {
    throw new Error(`parsing PCK leaf certificate: ${err instanceof Error ? err.message : String(err)}`);
  }
}
