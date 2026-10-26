import type { ASN1Obj } from '@freedomofpress/crypto-browser';
import type { X509Certificate } from '@freedomofpress/sigstore-browser';
import { parseJSON } from '../encoding.js';
import { buffer, checkTime, der, hex, integer, pemCertificates, requireThat, unhex, verifyChain, verifyCRL, verifyEC } from '../quote/crypto.js';

export interface PCSResponse { url: string; body: Uint8Array; headers: Record<string, string[]> }
export class PCSReplay {
  private readonly responses = new Map<string, PCSResponse>();
  constructor(responses: PCSResponse[]) {
    for (const r of responses) {
      const key = this.key(r.url);
      requireThat(!this.responses.has(key), 'duplicate PCS collateral response'); this.responses.set(key, r);
    }
  }
  private key(url: string): string {
    const parsed = new URL(url); parsed.searchParams.delete('tcbEvaluationDataNumber'); parsed.searchParams.sort();
    requireThat(parsed.protocol === 'https:' && !parsed.username && !parsed.password && !parsed.hash, 'invalid PCS collateral URL');
    return parsed.toString().toLowerCase();
  }
  get(url: string): PCSResponse {
    const response = this.responses.get(this.key(url)); requireThat(response, `missing Intel PCS response for ${url}`); return response;
  }
}
function members(obj: ASN1Obj): Map<string, ASN1Obj> {
  requireThat(obj.tag.toDER() === 0x30, 'expected ASN.1 sequence');
  const result = new Map<string, ASN1Obj>();
  for (const item of obj.subs) {
    requireThat(item.tag.toDER() === 0x30 && item.subs.length === 2, 'invalid PCK extension item');
    const oid = item.subs[0].toOID(); requireThat(!result.has(oid), 'duplicate PCK extension item'); result.set(oid, item.subs[1]);
  }
  return result;
}
export interface PCKExtensions { ppid: string; fmspc: string; pceID: string; pceSVN: number; cpuSVN: number[] }
export function pckExtensions(cert: X509Certificate): PCKExtensions {
  requireThat(cert.extensions.length === 6, 'PCK certificate must carry six extensions');
  const prefix = '1.2.840.113741.1.13.1';
  const extension = cert.extension(prefix); requireThat(extension, 'missing PCK SGX extension');
  const values = members(der(extension.value));
  for (const key of values.keys()) requireThat(['1', '2', '3', '4', '5', '6', '7'].some(s => key === `${prefix}.${s}`), 'unknown PCK SGX extension');
  const field = (suffix: string): ASN1Obj => { const v = values.get(`${prefix}.${suffix}`); requireThat(v, `missing PCK field ${suffix}`); return v; };
  const octets = (suffix: string, size: number): string => { const v = field(suffix); requireThat(v.tag.isOctetString() && v.value.length === size, 'invalid PCK octet string'); return hex(v.value); };
  const tcb = members(field('2')); requireThat(tcb.size === 18, 'PCK TCB must contain all 18 components');
  const component = (i: number): ASN1Obj => { const v = tcb.get(`${prefix}.2.${i}`); requireThat(v, `missing PCK TCB component ${i}`); return v; };
  const cpuSVN = Array.from({ length: 16 }, (_, i) => Number(integer(component(i + 1), 255n)));
  const cpuRaw = component(18); requireThat(cpuRaw.tag.isOctetString() && cpuRaw.value.length === 16, 'invalid PCK CPU SVN');
  return { ppid: octets('1', 16), pceID: octets('3', 2), fmspc: octets('4', 6), pceSVN: Number(integer(component(17), 65535n)), cpuSVN };
}
export function crlURL(cert: X509Certificate): string {
  const ext = cert.extension('2.5.29.31'); requireThat(ext, 'certificate has no CRL distribution point');
  const urls: string[] = [];
  const walk = (node: ASN1Obj): void => {
    if (node.tag.isContextSpecific(6)) urls.push(new TextDecoder('utf-8', { fatal: true }).decode(node.value));
    else if (node.tag.constructed) node.subs.forEach(walk);
  };
  walk(der(ext.value)); requireThat(urls.length === 1, 'certificate must have exactly one CRL distribution point'); return urls[0];
}
function issuerChain(response: PCSResponse, name: string): X509Certificate[] {
  const values = Object.entries(response.headers).filter(([key]) => key.toLowerCase() === name.toLowerCase());
  requireThat(values.length === 1 && values[0][1].length === 1, `missing or ambiguous ${name} header`);
  const chain = pemCertificates(decodeURIComponent(values[0][1][0]));
  requireThat(chain.length === 2, 'PCS issuer chain must have signer and root'); return chain;
}

// Full strict parsing happens first, so this scanner only locates the exact
// signed object bytes; it never chooses a different duplicate member value.
function rawMember(text: string, key: string): string {
  let i = 0;
  const ws = () => { while (/\s/.test(text[i] ?? '') && i < text.length) i++; };
  const string = (): string => {
    const start = i++; while (i < text.length) { if (text[i++] === '"') return text.slice(start, i); if (text[i - 1] === '\\') i++; }
    throw new Error('unterminated PCS JSON string');
  };
  const skip = (): void => {
    ws(); if (text[i] === '"') { string(); return; }
    if (text[i] === '{' || text[i] === '[') {
      const end = text[i++] === '{' ? '}' : ']';
      while (i < text.length && text[i] !== end) { if (text[i] === '"') string(); else if (text[i] === '{' || text[i] === '[') skip(); else i++; }
      i++; return;
    }
    while (i < text.length && !/[\s,}\]]/.test(text[i])) i++;
  };
  ws(); requireThat(text[i++] === '{', 'PCS response must be an object');
  while (i < text.length) {
    ws(); if (text[i] === '}') break;
    const name = JSON.parse(string()); ws(); requireThat(text[i++] === ':', 'invalid PCS response'); ws();
    const start = i; skip(); if (name === key) return text.slice(start, i);
    ws(); if (text[i] === ',') i++; else break;
  }
  throw new Error(`PCS response missing ${key}`);
}
export async function signedPCS(replay: PCSReplay, url: string, name: 'tcbInfo' | 'enclaveIdentity', anchors: X509Certificate[], rootCRL: Uint8Array, now: Date): Promise<any> {
  const response = replay.get(url);
  const text = new TextDecoder('utf-8', { fatal: true }).decode(response.body);
  const parsed = parseJSON(text);
  requireThat(parsed && typeof parsed === 'object' && !Array.isArray(parsed) && Object.keys(parsed).length === 2 && parsed[name] && typeof parsed.signature === 'string', 'invalid signed PCS response');
  const chain = issuerChain(response, name === 'tcbInfo' ? 'Tcb-Info-Issuer-Chain' : 'Sgx-Enclave-Identity-Issuer-Chain');
  requireThat(chain[0].subjectDN.get('CN') === 'Intel SGX TCB Signing', 'unexpected PCS signing certificate');
  await verifyChain(chain, anchors, now);
  await verifyCRL(rootCRL, chain[1], now, [chain[0]]);
  const key = await crypto.subtle.importKey('spki', buffer(chain[0].publicKey), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  await verifyEC(key, unhex(parsed.signature, 64), new TextEncoder().encode(rawMember(text, name)));
  const value = parsed[name];
  requireThat(value.id === (name === 'tcbInfo' ? 'TDX' : 'TD_QE') && value.version === (name === 'tcbInfo' ? 3 : 2), 'unsupported PCS collateral version');
  requireThat(typeof value.issueDate === 'string' && typeof value.nextUpdate === 'string', 'missing PCS validity window');
  checkTime(new Date(value.issueDate), new Date(value.nextUpdate), now, name);
  requireThat(Number.isSafeInteger(value.tcbEvaluationDataNumber) && value.tcbEvaluationDataNumber >= 0 && Array.isArray(value.tcbLevels) && value.tcbLevels.length > 0, 'invalid PCS TCB fields');
  return value;
}
export async function verifyPCKCRLChain(response: PCSResponse, anchors: X509Certificate[], expectedIssuer: X509Certificate, now: Date): Promise<void> {
  const chain = issuerChain(response, 'Sgx-Pck-Crl-Issuer-Chain');
  requireThat(hex(chain[0].root.toDER()) === hex(expectedIssuer.root.toDER()), 'PCK CRL issuer chain mismatch');
  await verifyChain(chain, anchors, now, 6);
}
