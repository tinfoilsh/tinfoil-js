import type { X509Certificate } from '@freedomofpress/sigstore-browser';
import { ASN1Obj } from '@freedomofpress/crypto-browser';
import {
  SGX_EXTENSIONS_OID,
  SGX_FMSPC_OID,
  SGX_PCEID_OID,
  SGX_TCB_OID,
} from './constants.js';
import { AttestationError } from '../errors.js';

export interface PckExtensions {
  fmspc: string;
  pceid: string;
  sgxTcbComponentSvns: number[];
  pcesvn: number;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function findOidInSequence(seq: ASN1Obj, targetOid: string): ASN1Obj | undefined {
  for (const sub of seq.subs) {
    if (sub.subs.length >= 2 && sub.subs[0].toOID() === targetOid) {
      return sub.subs[1];
    }
  }
  return undefined;
}

export function parsePckExtensions(pckCert: X509Certificate): PckExtensions {
  const sgxExt = pckCert.extension(SGX_EXTENSIONS_OID);
  if (!sgxExt) {
    throw new AttestationError('PCK certificate missing SGX extensions (OID 1.2.840.113741.1.13.1)');
  }

  const sgxSeq = ASN1Obj.parseBuffer(sgxExt.value);

  // FMSPC (OID .4) — 6 bytes as hex
  const fmspcObj = findOidInSequence(sgxSeq, SGX_FMSPC_OID);
  if (!fmspcObj) {
    throw new AttestationError('PCK certificate missing FMSPC extension');
  }
  const fmspcBytes = fmspcObj.subs.length > 0 ? fmspcObj.subs[0].value : fmspcObj.value;
  const fmspc = bytesToHex(fmspcBytes);

  // PCEID (OID .3) — 2 bytes as hex
  const pceidObj = findOidInSequence(sgxSeq, SGX_PCEID_OID);
  if (!pceidObj) {
    throw new AttestationError('PCK certificate missing PCEID extension');
  }
  const pceidBytes = pceidObj.subs.length > 0 ? pceidObj.subs[0].value : pceidObj.value;
  const pceid = bytesToHex(pceidBytes);

  // TCB (OID .2) — sequence of 18 component SVNs
  const tcbObj = findOidInSequence(sgxSeq, SGX_TCB_OID);
  if (!tcbObj) {
    throw new AttestationError('PCK certificate missing TCB extension');
  }

  const sgxTcbComponentSvns: number[] = [];
  let pcesvn = 0;

  const PCESVN_OID = SGX_TCB_OID + '.17';
  const CPUSVN_OID = SGX_TCB_OID + '.18';

  // TCB sequence contains OID-value pairs for each component
  // Components 1-16 are SGX TCB SVNs (INTEGER), 17 is PCESVN (INTEGER), 18 is CPUSVN (OCTET STRING)
  for (const component of tcbObj.subs) {
    if (component.subs.length < 2) continue;
    const oid = component.subs[0].toOID();

    // Skip CPUSVN — it's an OCTET STRING, not an INTEGER, and not needed for TCB matching
    if (oid === CPUSVN_OID) continue;

    const valueObj = component.subs[1];
    let value: number;
    try {
      value = Number(valueObj.subs.length > 0 ? valueObj.subs[0].toInteger() : valueObj.toInteger());
    } catch {
      continue;
    }

    if (oid === PCESVN_OID) {
      pcesvn = value;
    } else if (oid.startsWith(SGX_TCB_OID + '.')) {
      const componentIndex = parseInt(oid.split('.').pop()!, 10) - 1;
      if (componentIndex >= 0 && componentIndex < 16) {
        sgxTcbComponentSvns[componentIndex] = value;
      }
    }
  }

  // Fill missing components with 0
  for (let i = 0; i < 16; i++) {
    if (sgxTcbComponentSvns[i] === undefined) {
      sgxTcbComponentSvns[i] = 0;
    }
  }

  return { fmspc, pceid, sgxTcbComponentSvns: sgxTcbComponentSvns.slice(0, 16), pcesvn };
}
