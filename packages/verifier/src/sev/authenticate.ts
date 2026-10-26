import { Report } from './report.js';
import { AMD_GENOA, AMD_TURIN } from '../quote/roots.js';
import { buffer, certificate, concat, der, equal, integer, pemCertificates, requireThat, verifyChain, verifyCRL, verifyEC, zero } from '../quote/crypto.js';

export interface SEVEvidence { report: Uint8Array; vcekDer: Uint8Array; certChainPem: string; crlDer: Uint8Array }
export async function authenticateSEV(evidence: SEVEvidence, now: Date, rootPem?: string): Promise<Report> {
  const report = new Report(evidence.report);
  const vcek = certificate(evidence.vcekDer), chain = pemCertificates(evidence.certChainPem);
  requireThat(chain.length === 2, 'AMD chain must contain ASK then ARK');
  const pinned = pemCertificates(rootPem ?? (report.product === 'Genoa' ? AMD_GENOA : AMD_TURIN));
  const [ask, ark] = chain;
  requireThat(ark.subjectDN.get('CN') === `ARK-${report.product}` && ask.subjectDN.get('CN') === `SEV-${report.product}`, 'AMD certificate product mismatch');
  requireThat(vcek.subjectDN.get('CN') === 'SEV-VCEK', 'invalid VCEK certificate name');
  for (const cert of [vcek, ask, ark]) {
    for (const [name, value] of Object.entries({ C: 'US', L: 'Santa Clara', ST: 'CA', O: 'Advanced Micro Devices', OU: 'Engineering' })) {
      requireThat(cert.subjectDN.get(name) === value, `invalid AMD certificate ${name}`);
    }
  }
  await verifyChain([vcek, ask, ark], [pinned[pinned.length - 1]], now);
  // AMD's product CRL is issued by ARK and revokes ASK certificates.
  await verifyCRL(evidence.crlDer, ark, now, [ask, vcek]);
  requireThat(vcek.signatureAlgorithmOid === '1.2.840.113549.1.1.10' && vcek.signatureAlgorithm.toLowerCase().replace('-', '') === 'sha384', 'VCEK must be signed with RSA-PSS SHA-384');
  const ext = (suffix: string): Uint8Array => {
    const value = vcek.extension(`1.3.6.1.4.1.3704.1.${suffix}`);
    requireThat(value, `missing VCEK extension ${suffix}`); return value.value;
  };
  const number = (suffix: string) => Number(integer(der(ext(suffix)), 255n));
  const version = number('1');
  requireThat(version === (report.product === 'Turin' ? 1 : 0), 'VCEK TCB format differs from report product');
  const productName = der(ext('2'));
  requireThat(productName.tag.toDER() === 0x16 && productName.value.length > 0, 'invalid VCEK product name');
  // Report v3 CPUID is authoritative: deployed Genoa certificates may carry
  // an incorrect product string, documented by AMD and go-sev-guest.
  requireThat(!vcek.extension('1.3.6.1.4.1.3704.1.5'), 'VLEK certificate cannot authenticate a VCEK report');
  const hwidSize = report.product === 'Turin' ? 8 : 64;
  const encodedHWID = ext('4');
  const hwid = encodedHWID.length === hwidSize ? encodedHWID : (() => {
    const value = der(encodedHWID); requireThat(value.tag.isOctetString(), 'invalid VCEK HWID'); return value.value;
  })();
  requireThat(hwid.length === hwidSize && equal(hwid, report.chipID.slice(0, hwidSize)), 'VCEK HWID does not match report CHIP_ID');
  if (hwidSize === 8) requireThat(zero(report.chipID.slice(8)), 'nonzero reserved Turin CHIP_ID bytes');
  const tcb = report.reportedTCB;
  for (const [name, suffix] of [['bl_spl', '3.1'], ['tee_spl', '3.2'], ['snp_spl', '3.3'], ['ucode_spl', '3.8']] as const) {
    requireThat(number(suffix) === tcb[name], `VCEK ${name} does not match report TCB`);
  }
  for (const suffix of ['3.5', '3.6', '3.7']) requireThat(number(suffix) === 0, 'nonzero reserved VCEK TCB component');
  if (report.product === 'Turin') {
    requireThat(!vcek.extension('1.3.6.1.4.1.3704.1.3.4') && number('3.9') === tcb.fmc_spl, 'invalid VCEK Turin FMC component');
  } else {
    requireThat(!vcek.extension('1.3.6.1.4.1.3704.1.3.9') && number('3.4') === 0, 'invalid VCEK Genoa reserved component');
  }
  const key = await crypto.subtle.importKey('spki', buffer(vcek.publicKey), { name: 'ECDSA', namedCurve: 'P-384' }, false, ['verify']);
  const sig = concat(report.field(0x2a0, 48).reverse(), report.field(0x2e8, 48).reverse());
  await verifyEC(key, sig, report.field(0, 0x2a0), 'SHA-384');
  return report;
}
