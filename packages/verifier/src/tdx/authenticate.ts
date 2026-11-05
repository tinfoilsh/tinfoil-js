import { TDXQuote } from './quote.js';
import { crlURL, pckExtensions, PCSReplay, signedPCS, verifyPCKCRLChain, type PCSResponse } from './collateral.js';
import { INTEL_SGX } from '../quote/roots.js';
import { buffer, concat, digest, equal, pemCertificates, requireThat, unhex, verifyChain, verifyCRL, verifyEC } from '../quote/crypto.js';

export interface AuthenticatedTDX { quote: TDXQuote; identity: string; tcbEvaluationDataNumber: number }
function masked(actual: Uint8Array, mask: unknown, expected: unknown): void {
  requireThat(typeof mask === 'string' && typeof expected === 'string', 'missing Intel identity mask');
  const m = unhex(mask, actual.length), e = unhex(expected, actual.length);
  requireThat(actual.every((b, i) => (b & m[i]) === e[i]), 'Intel identity masked field mismatch');
}
function number(value: unknown, max = 65535): number {
  requireThat(Number.isSafeInteger(value) && (value as number) >= 0 && (value as number) <= max, 'invalid Intel TCB component'); return value as number;
}
function level(levels: any[], predicate: (tcb: any) => boolean, label: string): void {
  requireThat(Array.isArray(levels) && levels.length > 0, `missing ${label} TCB levels`);
  const selected = levels.find(item => item && item.tcb && predicate(item.tcb));
  requireThat(selected && selected.tcbStatus === 'UpToDate', `${label} TCB is not up to date`);
}
export async function authenticateTDX(raw: Uint8Array, responses: PCSResponse[], now: Date, rootPem?: string): Promise<AuthenticatedTDX> {
  const quote = new TDXQuote(raw), chain = pemCertificates(quote.certificateChain);
  requireThat(chain.length === 3, 'TDX quote must carry PCK, intermediate and root certificates');
  const [pck, intermediate, root] = chain;
  requireThat(root.subjectDN.get('CN') === 'Intel SGX Root CA' && pck.subjectDN.get('CN') === 'Intel SGX PCK Certificate', 'invalid Intel certificate profile');
  const caName = intermediate.subjectDN.get('CN');
  requireThat(caName === 'Intel SGX PCK Platform CA' || caName === 'Intel SGX PCK Processor CA', 'unsupported PCK issuer');
  for (const cert of chain) requireThat(cert.signatureAlgorithmOid === '1.2.840.10045.4.3.2', 'Intel certificate requires ECDSA SHA-256');
  const anchors = pemCertificates(rootPem ?? INTEL_SGX);
  await verifyChain(chain, anchors, now);
  const pckExt = pckExtensions(pck), replay = new PCSReplay(responses);
  const rootCRL = replay.get(crlURL(root)).body;
  await verifyCRL(rootCRL, root, now, [intermediate]);
  const ca = caName === 'Intel SGX PCK Platform CA' ? 'platform' : 'processor';
  const crl = replay.get(`https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=${ca}&encoding=der`);
  await verifyPCKCRLChain(crl, anchors, intermediate, now);
  await verifyCRL(crl.body, intermediate, now, [pck]);
  const tcb = await signedPCS(replay, `https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=${pckExt.fmspc}`, 'tcbInfo', anchors, rootCRL, now);
  const qe = await signedPCS(replay, 'https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity', 'enclaveIdentity', anchors, rootCRL, now);
  const attestKey = await crypto.subtle.importKey('raw', buffer(concat(new Uint8Array([4]), quote.attestationKey)), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  await verifyEC(attestKey, quote.signature, quote.bytes.slice(0, 0x278));
  const pckKey = await crypto.subtle.importKey('spki', buffer(pck.publicKey), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  await verifyEC(pckKey, quote.qeSignature, quote.qeReport);
  requireThat(equal(quote.qeReport.slice(0x140), concat(await digest('SHA-256', concat(quote.attestationKey, quote.authData)), new Uint8Array(32))), 'QE report does not bind the attestation key and authentication data');
  requireThat(typeof tcb.fmspc === 'string' && tcb.fmspc.toLowerCase() === pckExt.fmspc && typeof tcb.pceId === 'string' && tcb.pceId.toLowerCase() === pckExt.pceID, 'TCB collateral does not describe PCK platform');
  requireThat(tcb.tcbType === 0, 'unsupported Intel TCB type');
  requireThat(tcb.tdxModule && equal(quote.field(0x40, 48), unhex(tcb.tdxModule.mrsigner, 48)), 'TDX module signer mismatch');
  masked(quote.field(0x70, 8), tcb.tdxModule.attributesMask, tcb.tdxModule.attributes);
  const tee = quote.teeTCBSVN;
  level(tcb.tcbLevels, candidate => {
    requireThat(Array.isArray(candidate.sgxtcbcomponents) && candidate.sgxtcbcomponents.length === 16 && Array.isArray(candidate.tdxtcbcomponents) && candidate.tdxtcbcomponents.length === 16, 'Intel TCB must describe all 16 components');
    return pckExt.cpuSVN.every((svn, i) => svn >= number(candidate.sgxtcbcomponents[i].svn, 255)) && pckExt.pceSVN >= number(candidate.pcesvn) && tee.every((svn, i) => (tee[1] > 0 && i < 2) || svn >= number(candidate.tdxtcbcomponents[i].svn, 255));
  }, 'platform');
  if (tee[1] > 0) {
    requireThat(Array.isArray(tcb.tdxModuleIdentities), 'missing TDX module identities');
    const id = 'TDX_' + tee[1].toString(16).toUpperCase().padStart(2, '0');
    const modules = tcb.tdxModuleIdentities.filter((m: any) => m.id === id);
    requireThat(modules.length === 1, 'missing or ambiguous TDX module identity');
    const module = modules[0];
    requireThat(equal(quote.field(0x40, 48), unhex(module.mrsigner, 48)), 'TDX module identity signer mismatch');
    masked(quote.field(0x70, 8), module.attributesMask, module.attributes);
    level(module.tcbLevels, candidate => tee[0] >= number(candidate.isvsvn), 'TDX module');
  }
  const qeView = new DataView(quote.qeReport.buffer);
  masked(quote.qeReport.slice(0x10, 0x14), qe.miscselectMask, qe.miscselect);
  masked(quote.qeReport.slice(0x30, 0x40), qe.attributesMask, qe.attributes);
  requireThat(equal(quote.qeReport.slice(0x80, 0xa0), unhex(qe.mrsigner, 32)), 'QE report signer mismatch');
  requireThat(qeView.getUint16(0x100, true) === number(qe.isvprodid), 'QE report product ID mismatch');
  level(qe.tcbLevels, candidate => qeView.getUint16(0x102, true) >= number(candidate.isvsvn), 'QE');
  return { quote, identity: pckExt.ppid, tcbEvaluationDataNumber: Math.min(tcb.tcbEvaluationDataNumber, qe.tcbEvaluationDataNumber) };
}
