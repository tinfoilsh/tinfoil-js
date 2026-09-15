// Engine-neutral crypto primitives over WebCrypto (globalThis.crypto.subtle),
// so the same code runs on Node and in browsers. WebCrypto ECDSA signatures
// are raw r||s (IEEE P1363); DER callers convert first. Verify helpers return
// false on any import/verify failure (mirroring the previous node:crypto
// wrappers); only import helpers throw.

const subtle = (): SubtleCrypto => globalThis.crypto.subtle;

export async function sha256(...chunks: Uint8Array[]): Promise<Uint8Array> {
  let total = 0;
  for (const c of chunks) total += c.length;
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.length;
  }
  return new Uint8Array(await subtle().digest("SHA-256", buf));
}

// importEcdsaSpki imports (and thereby validates, including the on-curve
// check) an ECDSA public key from SPKI DER.
export function importEcdsaSpki(spkiDer: Uint8Array, namedCurve: "P-256" | "P-384"): Promise<CryptoKey> {
  return subtle().importKey("spki", spkiDer as BufferSource, { name: "ECDSA", namedCurve }, false, ["verify"]);
}

// verifyP256Raw verifies a raw r||s (64-byte) ECDSA-P256-SHA256 signature.
export async function verifyP256Raw(spkiDer: Uint8Array, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
  try {
    const key = await importEcdsaSpki(spkiDer, "P-256");
    return await subtle().verify({ name: "ECDSA", hash: "SHA-256" }, key, signature as BufferSource, data as BufferSource);
  } catch {
    return false;
  }
}

// verifyP384Raw verifies a raw r||s (96-byte) ECDSA-P384-SHA384 signature.
export async function verifyP384Raw(spkiDer: Uint8Array, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
  try {
    const key = await importEcdsaSpki(spkiDer, "P-384");
    return await subtle().verify({ name: "ECDSA", hash: "SHA-384" }, key, signature as BufferSource, data as BufferSource);
  } catch {
    return false;
  }
}

// verifyRsaPssSha384 verifies an RSASSA-PSS SHA-384 signature with the given
// salt length.
export async function verifyRsaPssSha384(
  spkiDer: Uint8Array,
  signature: Uint8Array,
  data: Uint8Array,
  saltLength: number,
): Promise<boolean> {
  try {
    const key = await importRsaPssSha384(spkiDer);
    return await subtle().verify({ name: "RSA-PSS", saltLength }, key, signature as BufferSource, data as BufferSource);
  } catch {
    return false;
  }
}

// importRsaPssSha384 imports an RSA public key from SPKI DER. WebCrypto only
// accepts the rsaEncryption AlgorithmIdentifier, while node:crypto's
// createPublicKey also accepted id-RSASSA-PSS; keys declared as RSASSA-PSS
// are re-labeled as rsaEncryption before a second attempt.
async function importRsaPssSha384(spkiDer: Uint8Array): Promise<CryptoKey> {
  const alg = { name: "RSA-PSS", hash: "SHA-384" };
  try {
    return await subtle().importKey("spki", spkiDer as BufferSource, alg, false, ["verify"]);
  } catch (err) {
    const relabeled = rsaPssSpkiToRsaEncryption(spkiDer);
    if (relabeled === undefined) throw err;
    return await subtle().importKey("spki", relabeled as BufferSource, alg, false, ["verify"]);
  }
}

// 06 09 2a 86 48 86 f7 0d 01 01 0a — id-RSASSA-PSS
const oidRsaPssDER = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
// 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 — AlgorithmIdentifier{rsaEncryption, NULL}
const rsaEncryptionAlgDER = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];

interface DERElement {
  contentStart: number;
  end: number;
}

function readDER(b: Uint8Array, off: number): DERElement | undefined {
  if (off + 2 > b.length) return undefined;
  let len = b[off + 1];
  let contentStart = off + 2;
  if (len === 0x80) return undefined;
  if (len > 0x80) {
    const n = len & 0x7f;
    if (n > 4 || off + 2 + n > b.length) return undefined;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[off + 2 + i];
    contentStart = off + 2 + n;
  }
  const end = contentStart + len;
  if (end > b.length) return undefined;
  return { contentStart, end };
}

function derEncodeLength(n: number): number[] {
  if (n < 0x80) return [n];
  const out: number[] = [];
  while (n > 0) {
    out.unshift(n & 0xff);
    n >>= 8;
  }
  return [0x80 | out.length, ...out];
}

// rsaPssSpkiToRsaEncryption rebuilds an SPKI whose AlgorithmIdentifier is
// id-RSASSA-PSS with rsaEncryption; undefined when the input is anything else.
function rsaPssSpkiToRsaEncryption(spkiDer: Uint8Array): Uint8Array | undefined {
  if (spkiDer[0] !== 0x30) return undefined;
  const outer = readDER(spkiDer, 0);
  if (outer === undefined || outer.end !== spkiDer.length) return undefined;
  if (spkiDer[outer.contentStart] !== 0x30) return undefined;
  const algSeq = readDER(spkiDer, outer.contentStart);
  if (algSeq === undefined) return undefined;
  if (spkiDer[algSeq.contentStart] !== 0x06) return undefined;
  const oid = readDER(spkiDer, algSeq.contentStart);
  if (oid === undefined || oid.end - algSeq.contentStart !== oidRsaPssDER.length) return undefined;
  for (let i = 0; i < oidRsaPssDER.length; i++) {
    if (spkiDer[algSeq.contentStart + i] !== oidRsaPssDER[i]) return undefined;
  }
  const rest = spkiDer.subarray(algSeq.end, outer.end); // BIT STRING subjectPublicKey
  const content = rsaEncryptionAlgDER.length + rest.length;
  const header = [0x30, ...derEncodeLength(content)];
  const out = new Uint8Array(header.length + content);
  out.set(header, 0);
  out.set(rsaEncryptionAlgDER, header.length);
  out.set(rest, header.length + rsaEncryptionAlgDER.length);
  return out;
}

// derEcdsaSignatureToRaw converts a DER ECDSA signature to the fixed-size raw
// r||s form WebCrypto verifies. Undefined on anything OpenSSL's DER decoder
// would reject (node's dsaEncoding:"der" behavior): non-canonical DER,
// negative or oversized components, trailing bytes — the caller treats
// undefined as verification failure, as node:crypto returned false.
export function derEcdsaSignatureToRaw(der: Uint8Array, coordSize: number): Uint8Array | undefined {
  if (der.length === 0 || der[0] !== 0x30) return undefined;
  const seq = readDER(der, 0);
  if (seq === undefined || seq.end !== der.length) return undefined;
  const out = new Uint8Array(2 * coordSize);
  let off = seq.contentStart;
  for (let comp = 0; comp < 2; comp++) {
    if (der[off] !== 0x02) return undefined;
    const int = readDER(der, off);
    if (int === undefined) return undefined;
    let c = int.contentStart;
    if (c === int.end) return undefined; // empty INTEGER
    if ((der[c] & 0x80) !== 0) return undefined; // negative
    if (der[c] === 0 && int.end - c > 1) {
      if ((der[c + 1] & 0x80) === 0) return undefined; // non-minimal
      c++;
    }
    const len = int.end - c;
    if (len > coordSize) return undefined;
    out.set(der.subarray(c, int.end), (comp + 1) * coordSize - len);
    off = int.end;
  }
  if (off !== seq.end) return undefined;
  return out;
}
