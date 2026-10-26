import { ASN1Obj } from '@freedomofpress/crypto-browser';
import { createECDH, createPrivateKey, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { certificate, der, pemCertificates, verifyChain, verifyCRL } from '../src/quote/crypto.js';
import { AMD_GENOA, AMD_TURIN } from '../src/quote/roots.js';

const now = new Date('2026-10-24T00:00:00Z');
const data = JSON.parse(readFileSync(new URL('fixtures/hardware-v3/x509-constraints.json', import.meta.url), 'utf8'));
const bytes = (name: string) => Uint8Array.from(Buffer.from(data[name], 'base64'));
const cert = (name: string) => certificate(bytes(name));

describe('portable certificate authentication', () => {
  it.each([['Genoa', AMD_GENOA], ['Turin', AMD_TURIN]])('validates pinned %s ASK and ARK signatures', async (_, pem) => {
    const [ask, ark] = pemCertificates(pem);
    await expect(verifyChain([ask, ark], [ark], now, 5)).resolves.toBeUndefined();
  });

  it('enforces the certificate use required by the authenticated object', async () => {
    const root = cert('root'), issuer = cert('issuer');
    await expect(verifyChain([cert('leaf'), issuer, root], [root], now)).resolves.toBeUndefined();
    await expect(verifyChain([cert('wrongUsageLeaf'), issuer, root], [root], now)).rejects.toThrow('key usage');
    await expect(verifyChain([issuer, root], [root], now, 6)).resolves.toBeUndefined();
    await expect(verifyChain([issuer, root], [root], now)).rejects.toThrow('key usage');
  });

  it('authenticates CRLs containing serials above uint64 and detects exact revocation', async () => {
    const issuer = cert('issuer'), leaf = cert('leaf');
    await expect(verifyCRL(bytes('otherCRL'), issuer, now, [leaf])).resolves.toBeUndefined();
    await expect(verifyCRL(bytes('revokedCRL'), issuer, now, [leaf])).rejects.toThrow('revoked');
  });
  it.each(['leaf', 'issuer', 'root'])('checks both validity endpoints of the %s certificate independently', async narrow => {
    const chain = [cert(`${narrow}WindowLeaf`), cert(`${narrow}WindowIssuer`), cert(`${narrow}WindowRoot`)];
    const start = new Date('2026-10-23T00:00:00Z'), end = new Date('2026-11-01T00:00:00Z');
    for (const at of [start, end]) await expect(verifyChain(chain, [chain[2]], at)).resolves.toBeUndefined();
    for (const at of [new Date(+start - 1), new Date(+end + 1)]) await expect(verifyChain(chain, [chain[2]], at)).rejects.toThrow('validity window');
  });

});

it('rejects malformed extensions in authentically signed CRLs', async () => {
  // The generator pins the issuer to P-256 private scalar 12.
  const d = Buffer.alloc(32); d[31] = 12;
  const ecdh = createECDH('prime256v1'); ecdh.setPrivateKey(d);
  const point = ecdh.getPublicKey();
  const key = createPrivateKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256', d: d.toString('base64url'), x: point.subarray(1, 33).toString('base64url'), y: point.subarray(33).toString('base64url') } });
  const tlv = (tag: number, ...values: number[][]) => { const value = values.flat(); return [tag, value.length, ...value]; };
  const oid = [6, 2, 42, 3], octets = [4, 1, 0], flag = [1, 1, 0];
  const extensions = [
    tlv(0x30, oid, octets), tlv(0x30, oid, flag, octets),
    tlv(0x30, [2, 1, 1], octets), tlv(0x30, oid, [2, 1, 0]),
    tlv(0x30, oid, [2, 1, 0], octets), tlv(0x30, oid),
    tlv(0x30, oid, flag, octets, octets), tlv(0x31, oid, octets),
  ];
  for (const [index, extension] of extensions.entries()) {
    for (const entryLevel of [false, true]) {
      const crl = der(bytes('otherCRL')), tbs = crl.subs[0];
      const encoded = tlv(0x30, extension);
      if (entryLevel) tbs.subs.at(-1)!.subs[0].subs.push(der(Uint8Array.from(encoded)));
      else tbs.subs.push(der(Uint8Array.from(tlv(0xa0, encoded))));
      const signature = sign('sha256', tbs.toDER(), key);
      crl.subs[2] = new ASN1Obj(crl.subs[2].tag, Uint8Array.from([0, ...signature]), []);
      const verify = verifyCRL(crl.toDER(), cert('issuer'), now, [cert('leaf')]);
      if (index < 2) await expect(verify).resolves.toBeUndefined();
      else await expect(verify).rejects.toThrow('invalid CRL extension structure');
    }
  }
});
