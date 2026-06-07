import { X509Certificate } from '@freedomofpress/sigstore-browser';
import { ASN1Obj } from '@freedomofpress/crypto-browser';
import type { TdxQuote } from './quote.js';
import type { PckCertificateChain } from './cert-chain.js';
import type { PckExtensions } from './pck-extensions.js';
import {
  INTEL_PCS_BASE_URL,
  TDX_PROXY_HOST,
  MINIMUM_TCB_EVALUATION_DATA_NUMBER,
  PCS_TCB_INFO_PATH,
  PCS_QE_IDENTITY_PATH,
  PCS_PCK_CRL_PATH,
  PCS_ROOT_CA_CRL_URL,
  ACCEPTABLE_TCB_STATUSES,
  INTEL_SGX_ROOT_CA_PEM,
} from './constants.js';
import { AttestationError, FetchError } from '../errors.js';

// --- Types ---

interface TcbComponent {
  svn: number;
  category?: string;
  type?: string;
}

interface TcbLevel {
  tcb: {
    sgxtcbcomponents: TcbComponent[];
    tdxtcbcomponents: TcbComponent[];
    pcesvn: number;
  };
  tcbDate: string;
  tcbStatus: string;
  advisoryIDs?: string[];
}

interface TdxModuleIdentity {
  id: string;
  mrsigner: string;
  attributes: string;
  attributesMask: string;
  tcbLevels: {
    tcb: { isvsvn: number };
    tcbDate: string;
    tcbStatus: string;
  }[];
}

interface TcbInfoV3 {
  id: string;
  version: number;
  issueDate: string;
  nextUpdate: string;
  fmspc: string;
  pceId: string;
  tcbType: number;
  tcbEvaluationDataNumber: number;
  tdxModule?: {
    mrsigner: string;
    attributes: string;
    attributesMask: string;
  };
  tdxModuleIdentities?: TdxModuleIdentity[];
  tcbLevels: TcbLevel[];
}

interface TcbInfoResponse {
  tcbInfo: TcbInfoV3;
  signature: string;
}

interface QeIdentityTcbLevel {
  tcb: { isvsvn: number };
  tcbDate: string;
  tcbStatus: string;
  advisoryIDs?: string[];
}

interface QeIdentityV2 {
  id: string;
  version: number;
  issueDate: string;
  nextUpdate: string;
  tcbEvaluationDataNumber: number;
  miscselect: string;
  miscselectMask: string;
  attributes: string;
  attributesMask: string;
  mrsigner: string;
  isvprodid: number;
  tcbLevels: QeIdentityTcbLevel[];
}

interface QeIdentityResponse {
  enclaveIdentity: QeIdentityV2;
  signature: string;
}

interface CacheEntry {
  body: string;
  headers: Record<string, string>;
  expiresAt: number;
}

export interface CollateralOptions {
  proxyHost?: string;
  cachePrefetchMs?: number;
  fetch?: typeof fetch;
  trustedRootPem?: string;
  now?: Date;
  minTcbEvaluationDataNumber?: number;
  acceptedQvResults?: string[];
}

export interface CollateralValidationResult {
  tcbStatus: string;
  advisoryIDs: string[];
  qvResult: string;
}

// --- Cache ---

const collateralCache = new Map<string, CacheEntry>();

// --- Fetch helpers ---

function buildProxyUrl(originalUrl: string, proxyHost: string): string {
  const parsed = new URL(originalUrl);
  return `https://${proxyHost}/${parsed.host}${parsed.pathname}${parsed.search}`;
}

async function fetchCollateral(
  url: string,
  opts: CollateralOptions,
): Promise<{ body: string; headers: Record<string, string> }> {
  const now = Date.now();
  const prefetchMs = opts.cachePrefetchMs ?? 3600_000;
  const cached = collateralCache.get(url);
  if (cached && now + prefetchMs < cached.expiresAt) {
    return { body: cached.body, headers: cached.headers };
  }

  const fetchUrl = opts.proxyHost ? buildProxyUrl(url, opts.proxyHost) : url;

  let response: Response;
  try {
    response = await (opts.fetch ?? fetch)(fetchUrl);
  } catch (e) {
    throw new FetchError(`Failed to fetch collateral from ${url}`, { cause: e as Error });
  }

  if (!response.ok) {
    throw new FetchError(`Collateral fetch failed: HTTP ${response.status} from ${url}`);
  }

  const body = await response.text();
  const headers: Record<string, string> = {};
  response.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });

  const nextUpdate = parseNextUpdate(url, body);
  if (nextUpdate > 0) {
    collateralCache.set(url, { body, headers, expiresAt: nextUpdate });
  }

  return { body, headers };
}

async function fetchCollateralBinary(
  url: string,
  opts: CollateralOptions,
): Promise<Uint8Array> {
  const fetchUrl = opts.proxyHost ? buildProxyUrl(url, opts.proxyHost) : url;

  let response: Response;
  try {
    response = await (opts.fetch ?? fetch)(fetchUrl);
  } catch (e) {
    throw new FetchError(`Failed to fetch collateral from ${url}`, { cause: e as Error });
  }

  if (!response.ok) {
    throw new FetchError(`Collateral fetch failed: HTTP ${response.status} from ${url}`);
  }

  return new Uint8Array(await response.arrayBuffer());
}

function parseNextUpdate(url: string, body: string): number {
  try {
    if (url.includes('/qe/identity')) {
      const resp = JSON.parse(body) as QeIdentityResponse;
      return new Date(resp.enclaveIdentity.nextUpdate).getTime();
    }
    if (url.includes('/tcb')) {
      const resp = JSON.parse(body) as TcbInfoResponse;
      return new Date(resp.tcbInfo.nextUpdate).getTime();
    }
  } catch {
    // ignore parse errors
  }
  return 0;
}

// --- TCB Info ---

async function fetchTcbInfo(
  fmspc: string,
  opts: CollateralOptions,
): Promise<TcbInfoResponse> {
  const minTcbEvaluationDataNumber = minimumTcbEvaluationDataNumber(opts);
  const url = `${INTEL_PCS_BASE_URL}${PCS_TCB_INFO_PATH}?fmspc=${fmspc}&tcbEvaluationDataNumber=${minTcbEvaluationDataNumber}`;
  const { body, headers } = await fetchCollateral(url, opts);
  const resp = JSON.parse(body) as TcbInfoResponse;

  assertJsonFreshness('TCB Info', resp.tcbInfo.issueDate, resp.tcbInfo.nextUpdate, validationTime(opts));

  if (resp.tcbInfo.tcbEvaluationDataNumber < minTcbEvaluationDataNumber) {
    throw new AttestationError(
      `TCB Info tcbEvaluationDataNumber ${resp.tcbInfo.tcbEvaluationDataNumber} is below minimum ${minTcbEvaluationDataNumber}`
    );
  }

  const rawTcbInfo = extractRawJsonField(body, 'tcbInfo');
  try {
    await verifyCollateralSignature(
      rawTcbInfo,
      resp.signature,
      headers['tcb-info-issuer-chain'] || headers['sgx-tcb-info-issuer-chain'],
      opts.trustedRootPem,
    );
  } catch (e) {
    throw new AttestationError(`TCB Info signature or chain verification failed: ${errorMessage(e)}`, { cause: e as Error });
  }

  return resp;
}

async function fetchQeIdentity(
  opts: CollateralOptions,
): Promise<QeIdentityResponse> {
  const minTcbEvaluationDataNumber = minimumTcbEvaluationDataNumber(opts);
  const url = `${INTEL_PCS_BASE_URL}${PCS_QE_IDENTITY_PATH}?tcbEvaluationDataNumber=${minTcbEvaluationDataNumber}`;
  const { body, headers } = await fetchCollateral(url, opts);
  const resp = JSON.parse(body) as QeIdentityResponse;

  assertJsonFreshness(
    'QE Identity',
    resp.enclaveIdentity.issueDate,
    resp.enclaveIdentity.nextUpdate,
    validationTime(opts),
  );

  if (resp.enclaveIdentity.tcbEvaluationDataNumber < minTcbEvaluationDataNumber) {
    throw new AttestationError(
      `QE Identity tcbEvaluationDataNumber ${resp.enclaveIdentity.tcbEvaluationDataNumber} is below minimum ${minTcbEvaluationDataNumber}`
    );
  }

  const rawEnclaveIdentity = extractRawJsonField(body, 'enclaveIdentity');
  try {
    await verifyCollateralSignature(
      rawEnclaveIdentity,
      resp.signature,
      headers['sgx-enclave-identity-issuer-chain'] || headers['enclave-identity-issuer-chain'],
      opts.trustedRootPem,
    );
  } catch (e) {
    throw new AttestationError(`QE Identity signature or chain verification failed: ${errorMessage(e)}`, { cause: e as Error });
  }

  return resp;
}

// --- Collateral Signature Verification ---

async function verifyCollateralSignature(
  jsonBody: string,
  signatureHex: string,
  issuerChainHeader?: string,
  trustedRootPem: string = INTEL_SGX_ROOT_CA_PEM,
): Promise<void> {
  if (!signatureHex) {
    throw new AttestationError('Collateral response missing signature');
  }

  const trustedRoot = X509Certificate.parse(trustedRootPem);

  let signingCert: X509Certificate;
  if (issuerChainHeader) {
    const decodedChain = decodeURIComponent(issuerChainHeader);
    const pemRegex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
    const pems: string[] = [];
    let match;
    while ((match = pemRegex.exec(decodedChain)) !== null) {
      pems.push(match[0]);
    }

    if (pems.length < 1) {
      throw new AttestationError('Collateral issuer chain header contains no certificates');
    }

    signingCert = X509Certificate.parse(pems[0]);

    // Verify the signing cert chains to the trusted Intel SGX Root CA
    if (pems.length === 1) {
      const signedByRoot = await signingCert.verify(trustedRoot);
      if (!signedByRoot) {
        throw new AttestationError('Collateral signing certificate not signed by Intel SGX Root CA');
      }
    } else if (pems.length >= 2) {
      const intermediateCert = X509Certificate.parse(pems[pems.length >= 3 ? 1 : 0]);
      const rootCert = pems.length >= 3 ? X509Certificate.parse(pems[2]) : trustedRoot;

      if (!rootCert.equals(trustedRoot)) {
        const rootKeyMatch = rootCert.publicKey.length === trustedRoot.publicKey.length &&
          rootCert.publicKey.every((b: number, i: number) => b === trustedRoot.publicKey[i]);
        if (!rootKeyMatch) {
          throw new AttestationError('Collateral signing certificate chain does not terminate at Intel SGX Root CA');
        }
      }

      const intermediateSignedByRoot = await intermediateCert.verify(rootCert);
      if (!intermediateSignedByRoot) {
        throw new AttestationError('Collateral intermediate certificate not signed by root');
      }

      if (pems.length >= 3) {
        const leafSignedByIntermediate = await signingCert.verify(intermediateCert);
        if (!leafSignedByIntermediate) {
          throw new AttestationError('Collateral signing certificate not signed by intermediate');
        }
      }
    }
  } else {
    signingCert = trustedRoot;
  }

  // Verify the signature (ECDSA-P256-SHA256) over the JSON body
  const sigBytes = hexToBytes(signatureHex);
  const dataBytes = new TextEncoder().encode(jsonBody);

  const publicKey = await signingCert.publicKeyObj;
  const valid = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    publicKey,
    sigBytes.buffer as ArrayBuffer,
    dataBytes.buffer as ArrayBuffer,
  );

  if (!valid) {
    throw new AttestationError('Collateral signature verification failed');
  }
}

// --- TCB Level Matching ---

function matchTcbLevel(
  pckSgxSvns: number[],
  pckPcesvn: number,
  quoteTdxSvns: Uint8Array,
  tcbLevels: TcbLevel[],
): { status: string; advisoryIDs: string[] } {
  // When a TDX module major version is present, bytes 0-1 are checked through
  // tdxModuleIdentities; the platform TCB level comparison starts at byte 2.
  const tdxComponentStart = quoteTdxSvns[1] && quoteTdxSvns[1] > 0 ? 2 : 0;

  for (const level of tcbLevels) {
    let matches = true;

    // Check SGX TCB components (from PCK certificate)
    for (let i = 0; i < 16; i++) {
      const required = level.tcb.sgxtcbcomponents[i]?.svn ?? 0;
      const actual = pckSgxSvns[i] ?? 0;
      if (actual < required) {
        matches = false;
        break;
      }
    }

    if (!matches) continue;

    // Check PCESVN
    if (pckPcesvn < level.tcb.pcesvn) continue;

    // Check TDX TCB components (from quote body's teeTcbSvn)
    for (let i = tdxComponentStart; i < 16; i++) {
      const required = level.tcb.tdxtcbcomponents?.[i]?.svn ?? 0;
      const actual = quoteTdxSvns[i] ?? 0;
      if (actual < required) {
        matches = false;
        break;
      }
    }

    if (matches) {
      return {
        status: level.tcbStatus,
        advisoryIDs: level.advisoryIDs ?? [],
      };
    }
  }

  return { status: 'Unknown', advisoryIDs: [] };
}

// --- QE Identity Validation ---

function validateQeIdentity(
  qeReport: TdxQuote['qeReport'],
  identity: QeIdentityV2,
): void {
  if (identity.id !== 'TD_QE') {
    throw new AttestationError(`QE Identity ID invalid: expected TD_QE, got ${identity.id}`);
  }
  if (identity.version !== 2) {
    throw new AttestationError(`QE Identity version invalid: expected 2, got ${identity.version}`);
  }

  // Validate MISCSELECT (with mask)
  const expectedMiscSelect = parseInt(identity.miscselect, 16);
  const miscSelectMask = parseInt(identity.miscselectMask, 16);
  if ((qeReport.miscSelect & miscSelectMask) !== (expectedMiscSelect & miscSelectMask)) {
    throw new AttestationError(
      `QE MISCSELECT mismatch: got 0x${qeReport.miscSelect.toString(16)}, ` +
      `expected 0x${expectedMiscSelect.toString(16)} with mask 0x${miscSelectMask.toString(16)}`
    );
  }

  // Validate attributes (with mask)
  const expectedAttributes = hexToBytes(identity.attributes);
  const attributesMask = hexToBytes(identity.attributesMask);
  if (qeReport.attributes.length !== expectedAttributes.length) {
    throw new AttestationError(
      `QE attributes length mismatch: got ${qeReport.attributes.length}, expected ${expectedAttributes.length}`
    );
  }
  for (let i = 0; i < expectedAttributes.length; i++) {
    if ((qeReport.attributes[i] & attributesMask[i]) !== (expectedAttributes[i] & attributesMask[i])) {
      throw new AttestationError('QE attributes do not match expected QE Identity attributes (after masking)');
    }
  }

  // Validate MRSIGNER
  const expectedMrSigner = hexToBytes(identity.mrsigner);
  if (qeReport.mrSigner.length !== expectedMrSigner.length) {
    throw new AttestationError(
      `QE MRSIGNER length mismatch: got ${qeReport.mrSigner.length}, expected ${expectedMrSigner.length}`
    );
  }
  for (let i = 0; i < expectedMrSigner.length; i++) {
    if (qeReport.mrSigner[i] !== expectedMrSigner[i]) {
      const actualHex = bytesToHexLocal(qeReport.mrSigner);
      throw new AttestationError(
        `QE MRSIGNER does not match expected Intel QE signer. ` +
        `Got ${actualHex}, expected ${identity.mrsigner}`
      );
    }
  }

  // Validate ISV_PROD_ID
  if (qeReport.isvProdId !== identity.isvprodid) {
    throw new AttestationError(
      `QE ISV_PROD_ID mismatch: got ${qeReport.isvProdId}, expected ${identity.isvprodid}`
    );
  }

  // Match QE TCB level to determine QE status
  let qeStatus = 'Unknown';
  for (const level of identity.tcbLevels) {
    if (qeReport.isvSvn >= level.tcb.isvsvn) {
      qeStatus = level.tcbStatus;
      break;
    }
  }

  if (!ACCEPTABLE_TCB_STATUSES.has(qeStatus)) {
    throw new AttestationError(
      `QE TCB status "${qeStatus}" is not acceptable. The Quoting Enclave may be outdated or revoked`
    );
  }
}

// --- TDX Module Identity Validation ---

function validateTdxModuleIdentity(
  quote: TdxQuote,
  tcbInfo: TcbInfoV3,
): void {
  if (tcbInfo.tdxModule) {
    const expectedMrSigner = hexToBytes(tcbInfo.tdxModule.mrsigner);
    if (quote.body.mrSignerSeam.length !== expectedMrSigner.length) {
      throw new AttestationError('TDX module MR_SIGNER_SEAM length mismatch');
    }
    for (let i = 0; i < expectedMrSigner.length; i++) {
      if (quote.body.mrSignerSeam[i] !== expectedMrSigner[i]) {
        throw new AttestationError(
          'TDX module MR_SIGNER_SEAM does not match expected Intel TDX module signer from TCB Info'
        );
      }
    }

    const expectedAttributes = hexToBytes(tcbInfo.tdxModule.attributes);
    const attributesMask = hexToBytes(tcbInfo.tdxModule.attributesMask);
    for (let i = 0; i < Math.min(quote.body.seamAttributes.length, expectedAttributes.length); i++) {
      if ((quote.body.seamAttributes[i] & attributesMask[i]) !== (expectedAttributes[i] & attributesMask[i])) {
        throw new AttestationError('TDX module SEAM_ATTRIBUTES do not match expected values from TCB Info (after masking)');
      }
    }
  }

  const teeTcbSvn = quote.body.teeTcbSvn;
  const moduleVersion = teeTcbSvn[1];

  if (moduleVersion > 0) {
    if (!tcbInfo.tdxModuleIdentities || tcbInfo.tdxModuleIdentities.length === 0) {
      throw new AttestationError(
        `TDX module version ${moduleVersion} requires tdxModuleIdentities in TCB Info, but none are present`
      );
    }

    const identityId = 'TDX_' + moduleVersion.toString(16).padStart(2, '0');
    const isvSvn = teeTcbSvn[0];

    const matchingIdentity = tcbInfo.tdxModuleIdentities.find(id => id.id === identityId);
    if (!matchingIdentity) {
      throw new AttestationError(
        `No TDX Module Identity found for ID "${identityId}" (module version ${moduleVersion})`
      );
    }

    let matchedStatus: string | undefined;
    for (const level of matchingIdentity.tcbLevels) {
      if (isvSvn >= level.tcb.isvsvn) {
        matchedStatus = level.tcbStatus;
        break;
      }
    }

    if (matchedStatus === undefined) {
      throw new AttestationError(
        `No matching TCB level for TDX Module Identity "${identityId}" with ISV SVN ${isvSvn}`
      );
    }

    if (matchedStatus !== 'UpToDate') {
      throw new AttestationError(
        `TDX Module TCB status "${matchedStatus}" is not acceptable for module "${identityId}". Expected "UpToDate"`
      );
    }
  }
}

// --- CRL Checking ---

const ECDSA_SIGNATURE_OIDS: Record<string, string> = {
  '1.2.840.10045.4.3.2': 'SHA-256',
  '1.2.840.10045.4.3.3': 'SHA-384',
  '1.2.840.10045.4.3.4': 'SHA-512',
};

function derEcdsaToP1363(derSig: Uint8Array, curveLen: number = 32): Uint8Array {
  const asn1 = ASN1Obj.parseBuffer(derSig);
  const r = asn1.subs[0].value;
  const s = asn1.subs[1].value;

  const result = new Uint8Array(curveLen * 2);

  const rTrimmed = r[0] === 0 && r.length > curveLen ? r.subarray(1) : r;
  const sTrimmed = s[0] === 0 && s.length > curveLen ? s.subarray(1) : s;

  result.set(rTrimmed, curveLen - rTrimmed.length);
  result.set(sTrimmed, curveLen * 2 - sTrimmed.length);

  return result;
}

async function verifyCrlSignature(crlDer: Uint8Array, issuerCert: X509Certificate): Promise<void> {
  const crl = ASN1Obj.parseBuffer(crlDer);

  if (crl.subs.length < 3) {
    throw new AttestationError('Invalid CRL structure: expected SEQUENCE with 3 elements');
  }

  const tbsCertListDer = crl.subs[0].toDER();
  const sigAlgOid = crl.subs[1].subs[0].toOID();
  const signatureRaw = crl.subs[2].value.subarray(1);

  const hashName = ECDSA_SIGNATURE_OIDS[sigAlgOid];
  if (!hashName) {
    throw new AttestationError(`Unsupported CRL signature algorithm OID: ${sigAlgOid}`);
  }

  const p1363Sig = derEcdsaToP1363(signatureRaw);
  const publicKey = await issuerCert.publicKeyObj;

  const valid = await crypto.subtle.verify(
    { name: 'ECDSA', hash: hashName },
    publicKey,
    new Uint8Array(p1363Sig).buffer as ArrayBuffer,
    new Uint8Array(tbsCertListDer).buffer as ArrayBuffer,
  );

  if (!valid) {
    throw new AttestationError('CRL signature verification failed: CRL was not signed by the expected CA');
  }
}

function parseRevokedSerialsFromDer(crlDer: Uint8Array): Uint8Array[] {
  const serials: Uint8Array[] = [];
  const crl = ASN1Obj.parseBuffer(crlDer);
  const tbsCertList = crl.subs[0];

  for (const sub of tbsCertList.subs) {
    if (sub.tag.number === 0x10 && sub.subs.length > 0 && sub.subs[0].tag.number === 0x10) {
      for (const entry of sub.subs) {
        if (entry.subs.length > 0) {
          serials.push(entry.subs[0].value);
        }
      }
      break;
    }
  }
  return serials;
}

function parseAsn1Time(obj: ASN1Obj): Date {
  const text = new TextDecoder().decode(obj.value);
  let year: number;
  let offset: number;

  if (obj.tag.number === 0x17) {
    const twoDigitYear = Number.parseInt(text.slice(0, 2), 10);
    year = twoDigitYear >= 50 ? 1900 + twoDigitYear : 2000 + twoDigitYear;
    offset = 2;
  } else if (obj.tag.number === 0x18) {
    year = Number.parseInt(text.slice(0, 4), 10);
    offset = 4;
  } else {
    throw new AttestationError(`Unsupported ASN.1 time tag ${obj.tag.number}`);
  }

  const month = Number.parseInt(text.slice(offset, offset + 2), 10) - 1;
  const day = Number.parseInt(text.slice(offset + 2, offset + 4), 10);
  const hour = Number.parseInt(text.slice(offset + 4, offset + 6), 10);
  const minute = Number.parseInt(text.slice(offset + 6, offset + 8), 10);
  const second = Number.parseInt(text.slice(offset + 8, offset + 10), 10);

  return new Date(Date.UTC(year, month, day, hour, minute, second));
}

function parseCrlNextUpdate(crlDer: Uint8Array): Date {
  const crl = ASN1Obj.parseBuffer(crlDer);
  const tbsCertList = crl.subs[0];
  if (!tbsCertList) {
    throw new AttestationError('Invalid CRL structure: missing TBSCertList');
  }

  let pos = 0;
  if (tbsCertList.subs[pos]?.tag.number === 0x02) {
    pos++;
  }
  pos += 3; // signature, issuer, thisUpdate

  const nextUpdate = tbsCertList.subs[pos];
  if (!nextUpdate || (nextUpdate.tag.number !== 0x17 && nextUpdate.tag.number !== 0x18)) {
    throw new AttestationError('CRL missing nextUpdate');
  }

  return parseAsn1Time(nextUpdate);
}

function assertCrlFreshness(label: string, crlDer: Uint8Array, now: Date): void {
  const nextUpdate = parseCrlNextUpdate(crlDer);
  if (nextUpdate.getTime() <= now.getTime()) {
    throw new AttestationError(`${label} has expired: nextUpdate ${nextUpdate.toISOString()} <= ${now.toISOString()}`);
  }
}

function getPckCaType(chain: PckCertificateChain): string {
  const cn = chain.intermediate.subjectDN.get('CN') ?? '';
  if (cn.includes('Platform')) return 'platform';
  return 'processor';
}

async function fetchAndCheckCrls(
  chain: PckCertificateChain,
  opts: CollateralOptions,
): Promise<void> {
  const caType = getPckCaType(chain);
  const pckCrlUrl = `${INTEL_PCS_BASE_URL}${PCS_PCK_CRL_PATH}?ca=${caType}&encoding=der`;
  const [pckCrlDer, rootCrlDer] = await Promise.all([
    fetchCollateralBinary(pckCrlUrl, opts),
    fetchCollateralBinary(PCS_ROOT_CA_CRL_URL, opts),
  ]);

  const now = validationTime(opts);
  assertCrlFreshness('PCK CRL', pckCrlDer, now);
  assertCrlFreshness('Root CRL', rootCrlDer, now);

  await Promise.all([
    verifyCrlSignature(pckCrlDer, chain.intermediate).catch((e: unknown) => {
      throw new AttestationError(`PCK CRL signature verification failed: ${errorMessage(e)}`, { cause: e as Error });
    }),
    verifyCrlSignature(rootCrlDer, chain.root).catch((e: unknown) => {
      throw new AttestationError(`Root CRL signature verification failed: ${errorMessage(e)}`, { cause: e as Error });
    }),
  ]);

  const pckRevokedSerials = parseRevokedSerialsFromDer(pckCrlDer);
  const rootRevokedSerials = parseRevokedSerialsFromDer(rootCrlDer);

  const allRevokedSerials = [...pckRevokedSerials, ...rootRevokedSerials];
  chain.checkRevocation(allRevokedSerials);
}

// --- Main Entry Point ---

export async function evaluateCollateral(
  quote: TdxQuote,
  chain: PckCertificateChain,
  pckExtensions: PckExtensions,
  opts: CollateralOptions = {},
): Promise<CollateralValidationResult> {
  const resolvedOpts: CollateralOptions = {
    proxyHost: opts.proxyHost ?? TDX_PROXY_HOST,
    cachePrefetchMs: opts.cachePrefetchMs ?? 3600_000,
    fetch: opts.fetch,
    trustedRootPem: opts.trustedRootPem,
    now: opts.now,
    minTcbEvaluationDataNumber: opts.minTcbEvaluationDataNumber,
    acceptedQvResults: opts.acceptedQvResults,
  };
  // Fetch all collateral in parallel
  const [tcbInfoResp, qeIdentityResp] = await Promise.all([
    fetchTcbInfo(pckExtensions.fmspc, resolvedOpts),
    fetchQeIdentity(resolvedOpts),
    fetchAndCheckCrls(chain, resolvedOpts),
  ]);

  const tcbInfo = tcbInfoResp.tcbInfo;

  // Validate TDX module identity (MR_SIGNER_SEAM, SEAM_ATTRIBUTES against TCB Info)
  validateTdxModuleIdentity(quote, tcbInfo);

  // Validate QE Identity (MR_SIGNER, attributes, ISV_PROD_ID, ISV_SVN)
  validateQeIdentity(quote.qeReport, qeIdentityResp.enclaveIdentity);

  // Match TCB level and reject unacceptable statuses
  const { status, advisoryIDs } = matchTcbLevel(
    pckExtensions.sgxTcbComponentSvns,
    pckExtensions.pcesvn,
    quote.body.teeTcbSvn,
    tcbInfo.tcbLevels,
  );

  if (!ACCEPTABLE_TCB_STATUSES.has(status)) {
    throw new AttestationError(
      `Platform TCB status "${status}" is not acceptable. ` +
      `The platform's TCB may be outdated or revoked. Acceptable statuses: ${[...ACCEPTABLE_TCB_STATUSES].join(', ')}`
    );
  }

  const qvResult = qvResultForTcbStatus(status);
  if (resolvedOpts.acceptedQvResults && resolvedOpts.acceptedQvResults.length > 0) {
    const accepted = new Set(resolvedOpts.acceptedQvResults.map(normalizeQvResult));
    if (!accepted.has(normalizeQvResult(qvResult))) {
      throw new AttestationError(
        `QV result ${qvResult} from TCB status ${status} not accepted by policy`
      );
    }
  }

  return { tcbStatus: status, advisoryIDs, qvResult };
}

export async function validateCollateral(
  quote: TdxQuote,
  chain: PckCertificateChain,
  pckExtensions: PckExtensions,
  opts: CollateralOptions = {},
): Promise<void> {
  await evaluateCollateral(quote, chain, pckExtensions, opts);
}

// --- Raw JSON extraction ---

function extractRawJsonField(body: string, fieldName: string): string {
  const key = `"${fieldName}"`;
  const keyIndex = body.indexOf(key);
  if (keyIndex === -1) {
    throw new AttestationError(`Field "${fieldName}" not found in collateral response`);
  }

  let pos = keyIndex + key.length;
  while (pos < body.length && body[pos] !== ':') pos++;
  pos++;
  while (pos < body.length && (body[pos] === ' ' || body[pos] === '\t' || body[pos] === '\n' || body[pos] === '\r')) pos++;

  if (pos >= body.length || body[pos] !== '{') {
    throw new AttestationError(`Expected object value for field "${fieldName}"`);
  }

  let depth = 0;
  let inString = false;
  let escape = false;
  const start = pos;

  for (; pos < body.length; pos++) {
    const ch = body[pos];
    if (escape) {
      escape = false;
      continue;
    }
    if (inString) {
      if (ch === '\\') escape = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') {
      inString = true;
    } else if (ch === '{') {
      depth++;
    } else if (ch === '}') {
      depth--;
      if (depth === 0) {
        return body.substring(start, pos + 1);
      }
    }
  }

  throw new AttestationError(`Unterminated object value for field "${fieldName}"`);
}

// --- Utilities ---

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHexLocal(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function validationTime(opts: CollateralOptions): Date {
  return opts.now ?? new Date();
}

function minimumTcbEvaluationDataNumber(opts: CollateralOptions): number {
  return opts.minTcbEvaluationDataNumber ?? MINIMUM_TCB_EVALUATION_DATA_NUMBER;
}

function assertJsonFreshness(label: string, issueDate: string, nextUpdate: string, now: Date): void {
  const issuedAt = new Date(issueDate);
  const expiresAt = new Date(nextUpdate);

  if (Number.isNaN(issuedAt.getTime()) || Number.isNaN(expiresAt.getTime())) {
    throw new AttestationError(`${label} has invalid issueDate or nextUpdate`);
  }
  if (issuedAt.getTime() > now.getTime()) {
    throw new AttestationError(`${label} is not yet valid: issueDate ${issuedAt.toISOString()} > ${now.toISOString()}`);
  }
  if (expiresAt.getTime() <= now.getTime()) {
    throw new AttestationError(`${label} has expired: nextUpdate ${expiresAt.toISOString()} <= ${now.toISOString()}`);
  }
}

function qvResultForTcbStatus(status: string): string {
  switch (status) {
    case 'UpToDate':
      return 'OK';
    case 'SWHardeningNeeded':
      return 'SW_HARDENING_NEEDED';
    case 'ConfigurationNeeded':
      return 'CONFIGURATION_NEEDED';
    case 'ConfigurationAndSWHardeningNeeded':
      return 'CONFIGURATION_AND_SW_HARDENING_NEEDED';
    default:
      return status.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toUpperCase();
  }
}

function normalizeQvResult(result: string): string {
  return result.trim().toUpperCase();
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
