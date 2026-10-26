import {
  ASN1Obj,
  importKey,
  verifySignature,
} from "@freedomofpress/crypto-browser";
import {
  SigstoreVerifier,
  X509Certificate,
  verifyBundleTimestamp,
  type TrustedRoot,
} from "@freedomofpress/sigstore-browser";
import {
  array,
  base64,
  canonicalJSON,
  concat,
  equal,
  fields,
  hex,
  nonempty,
  object,
  parseJSON,
  sha256,
  string,
  text,
  unbase64,
  unhex,
  utf8,
} from "./encoding.js";
import productionRoot from "./sigstore-trusted-root.js";
import { der as strictDER } from "./quote/crypto.js";
export type SigstoreRoot = TrustedRoot;
export const PAYLOAD_TYPE = "application/vnd.in-toto+json";
export const STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
export function pae(
  payload: Uint8Array,
  payloadType = PAYLOAD_TYPE,
): Uint8Array {
  const type = utf8(payloadType);
  return concat(
    utf8(`DSSEv1 ${type.length} `),
    type,
    utf8(` ${payload.length} `),
    payload,
  );
}
export class TrustInitializationError extends Error {
  readonly cause: unknown;
  constructor(cause: unknown) {
    super("Initializing embedded Sigstore trust failed");
    this.name = "TrustInitializationError";
    this.cause = cause;
  }
}
export function defaultSigstoreRoot(): SigstoreRoot {
  try {
    for (const log of [...productionRoot.tlogs, ...productionRoot.ctlogs]) {
      strictDER(unbase64(log.publicKey.rawBytes));
      if (unbase64(log.logId.keyId).length !== 32)
        throw new Error("Invalid built-in log identifier");
    }
    for (const ca of [
      ...productionRoot.certificateAuthorities,
      ...productionRoot.timestampAuthorities,
    ])
      for (const cert of ca.certChain.certificates)
        checkedCertificate(unbase64(cert.rawBytes));
  } catch (cause) {
    throw new TrustInitializationError(cause);
  }
  return structuredClone(productionRoot);
}
function checkedCertificate(der: Uint8Array): X509Certificate {
  const cert = new X509Certificate(strictDER(der));
  const seen = new Set<string>();
  for (const ext of cert.extensions) {
    const oid = ext.subs[0].toOID();
    if (seen.has(oid)) throw new Error("Duplicate certificate extension");
    seen.add(oid);
    if (
      ext.subs.length === 3 &&
      ext.subs[1].toBoolean() &&
      !["2.5.29.15", "2.5.29.19", "2.5.29.37", "2.5.29.17"].includes(oid)
    )
      throw new Error("Unsupported critical certificate extension");
  }
  return cert;
}
function keyPurpose(
  cert: X509Certificate,
  oid: string,
  required = false,
): void {
  const ext = cert.extension("2.5.29.37");
  if (required && !ext)
    throw new Error("Missing certificate extended key usage");
  if (
    ext &&
    !strictDER(ext.value).subs.some(
      (x) => x.toOID() === oid || x.toOID() === "2.5.29.37.0",
    )
  )
    throw new Error("Certificate extended key usage does not permit signing");
  const usage = cert.extension("2.5.29.15");
  if (usage && strictDER(usage.value).toBitString()[0] !== 1)
    throw new Error("Certificate key usage does not permit signing");
}

function integer(v: unknown, label: string): bigint {
  if (v === undefined) return 0n;
  if (typeof v === "number" && !Number.isSafeInteger(v))
    throw new Error(`Invalid ${label}`);
  if (!/^[0-9]+$/.test(String(v))) throw new Error(`Invalid ${label}`);
  return BigInt(String(v));
}
function inWindow(at: Date, valid: any): boolean {
  return (
    (!valid?.start || at.getTime() >= Date.parse(valid.start)) &&
    (!valid?.end || at.getTime() <= Date.parse(valid.end))
  );
}
async function logKey(log: any): Promise<CryptoKey> {
  return importKey(
    log.publicKey.keyDetails,
    log.publicKey.keyDetails,
    log.publicKey.rawBytes,
  );
}
export interface ParsedBundle {
  raw: any;
  vm: any;
  payload: Uint8Array;
  signature: Uint8Array;
  statement: any;
}
export function parseBundle(value: unknown, approval = false): ParsedBundle {
  const b = object(value, "Sigstore bundle");
  if (
    ![
      "application/vnd.dev.sigstore.bundle.v0.3+json",
      "application/vnd.dev.sigstore.bundle+json;version=0.3",
    ].includes(b.mediaType)
  )
    throw new Error("Only Sigstore v0.3 bundles are supported");
  if (
    approval &&
    b.mediaType !== "application/vnd.dev.sigstore.bundle.v0.3+json"
  )
    throw new Error("Approval requires the v0.3 bundle media type");
  const vm = object(b.verificationMaterial);
  if (vm.x509CertificateChain !== undefined || b.messageSignature !== undefined)
    throw new Error("Unsupported Sigstore content");
  const e = fields(b.dsseEnvelope, ["payload", "payloadType", "signatures"]);
  if (e.payloadType !== PAYLOAD_TYPE)
    throw new Error("Unsupported DSSE payload type");
  const signatures = array(e.signatures);
  if (signatures.length !== 1)
    throw new Error("DSSE requires exactly one signature");
  const signature = unbase64(nonempty(signatures[0].sig));
  const payload = unbase64(nonempty(e.payload));
  const statement = fields(parseJSON(payload), [
    "_type",
    "subject",
    "predicateType",
    "predicate",
  ]);
  if (statement._type !== STATEMENT_TYPE)
    throw new Error("Unsupported statement type");
  const subjects = array(statement.subject);
  if (!subjects.length) throw new Error("Statement has no subjects");
  for (const s of subjects) {
    fields(s, ["name", "digest"]);
    string(s.name);
    object(s.digest);
  }
  object(statement.predicate);
  return { raw: b, vm, payload, signature, statement };
}
async function verifyMerkle(entry: any, log: any): Promise<void> {
  const p = object(entry.inclusionProof, "inclusion proof");
  const index = integer(p.logIndex, "proof index"),
    size = integer(p.treeSize, "tree size");
  // Rekor's entry index is global across shards. The inclusion proof index is
  // local to the checkpoint's tree and is authenticated by that proof.
  if (size < 1n || index >= size)
    throw new Error("Invalid inclusion proof index");
  const inner = (index ^ (size - 1n)).toString(2).replace(/^0$/, "").length,
    border = (index >> BigInt(inner)).toString(2).split("1").length - 1;
  const hashes = array(p.hashes ?? []);
  if (hashes.length !== inner + border || hashes.length > 64)
    throw new Error("Invalid inclusion proof length");
  let hash = await sha256(
    concat(new Uint8Array([0]), unbase64(entry.canonicalizedBody)),
  );
  for (let i = 0; i < hashes.length; i++) {
    const h = unbase64(hashes[i]);
    if (h.length !== 32) throw new Error("Invalid Merkle node");
    hash = await sha256(
      i >= inner || (index >> BigInt(i)) & 1n
        ? concat(new Uint8Array([1]), h, hash)
        : concat(new Uint8Array([1]), hash, h),
    );
  }
  if (!equal(hash, unbase64(p.rootHash)))
    throw new Error("Merkle root mismatch");
  const envelope = nonempty(p.checkpoint?.envelope, "checkpoint"),
    split = envelope.indexOf("\n\n");
  if (split < 0) throw new Error("Malformed checkpoint");
  const note = envelope.slice(0, split + 1),
    lines = note.split("\n");
  if (
    lines.length < 4 ||
    integer(lines[1], "checkpoint size") !== size ||
    !equal(unbase64(lines[2]), hash)
  )
    throw new Error("Checkpoint tree mismatch");
  const signatureLines = envelope.slice(split + 2).split("\n");
  if (signatureLines.pop() !== "")
    throw new Error("Checkpoint signatures must end with newline");
  let verified = false;
  const key = await logKey(log),
    logID = unbase64(log.logId.keyId);
  for (const line of signatureLines) {
    const m = /^— ([^\s]+) ([A-Za-z0-9+/]+={0,2})$/.exec(line);
    if (!m) throw new Error("Malformed checkpoint signature");
    const sig = unbase64(m[2]);
    if (sig.length < 5) throw new Error("Short checkpoint signature");
    let hint = logID.subarray(0, 4);
    if (log.publicKey.keyDetails.includes("ED25519")) {
      const der = unbase64(log.publicKey.rawBytes);
      hint = (
        await sha256(
          concat(
            utf8(m[1] + "\n"),
            new Uint8Array([1]),
            der.subarray(der.length - 32),
          ),
        )
      ).subarray(0, 4);
    }
    if (
      equal(sig.subarray(0, 4), hint) &&
      (await verifySignature(key, utf8(note), sig.subarray(4)))
    )
      verified = true;
  }
  if (!verified) throw new Error("No trusted checkpoint signature");
}
async function bodyBinding(
  entry: any,
  b: ParsedBundle,
  signer: Uint8Array,
  certificate: boolean,
): Promise<void> {
  const body = object(parseJSON(unbase64(entry.canonicalizedBody)));
  if (
    body.kind !== entry.kindVersion?.kind ||
    body.apiVersion !== entry.kindVersion?.version
  )
    throw new Error("Rekor kind/version mismatch");
  const spec = object(body.spec);
  let sig: Uint8Array, loggedKey: Uint8Array, digest: string;
  if (body.kind === "dsse" && body.apiVersion === "0.0.1") {
    const ss = array(spec.signatures);
    if (ss.length !== 1) throw new Error("Invalid logged signature count");
    sig = unbase64(ss[0].signature);
    loggedKey = unbase64(ss[0].verifier);
    if (spec.payloadHash?.algorithm !== "sha256")
      throw new Error("Unsupported logged payload hash");
    digest = hex(await sha256(b.payload));
    if (spec.payloadHash.value !== digest)
      throw new Error("Logged payload hash mismatch");
  } else if (body.kind === "intoto" && body.apiVersion === "0.0.2") {
    const content = object(spec.content),
      e = object(content.envelope),
      ss = array(e.signatures);
    if (ss.length !== 1 || e.payloadType !== b.raw.dsseEnvelope.payloadType)
      throw new Error("Invalid logged envelope");
    sig = unbase64(text(unbase64(ss[0].sig)));
    loggedKey = unbase64(ss[0].publicKey);
    if (
      content.payloadHash?.algorithm !== "sha256" ||
      content.payloadHash.value !== hex(await sha256(b.payload))
    )
      throw new Error("Logged payload hash mismatch");
  } else if (body.kind === "hashedrekord" && body.apiVersion === "0.0.2") {
    const s = object(spec.hashedRekordV002);
    sig = unbase64(s.signature?.content);
    const v = object(s.signature?.verifier);
    if (certificate) {
      if (!v.x509Certificate || v.publicKey)
        throw new Error("Logged verifier is not a certificate");
      loggedKey = unbase64(v.x509Certificate.rawBytes);
    } else {
      if (
        !v.publicKey ||
        v.x509Certificate ||
        v.keyDetails !== "PKIX_ECDSA_P256_SHA_256"
      )
        throw new Error("Logged verifier is not the trusted approval key");
      loggedKey = unbase64(v.publicKey.rawBytes);
    }
    if (
      !["SHA2_256", "SHA256", "sha256"].includes(s.data?.algorithm) ||
      !equal(unbase64(s.data.digest), await sha256(pae(b.payload)))
    )
      throw new Error("Logged DSSE digest mismatch");
  } else throw new Error("Unsupported Rekor DSSE entry");
  if (!equal(sig, b.signature)) throw new Error("Logged signature mismatch");
  if (certificate) {
    const cert = X509Certificate.parse(
      loggedKey[0] === 45 ? text(loggedKey) : loggedKey,
    );
    if (!equal(cert.root.toDER(), signer))
      throw new Error("Logged signing certificate mismatch");
  } else if (!equal(loggedKey, signer))
    throw new Error("Logged signing public key mismatch");
}
export async function verifyLogEntries(
  b: ParsedBundle,
  root: SigstoreRoot,
  signer: Uint8Array,
  certificate: boolean,
): Promise<Date[]> {
  const entries = array(b.vm.tlogEntries, "transparency log entries");
  if (entries.length < 1 || entries.length > (certificate ? 32 : 8))
    throw new Error("Invalid transparency receipt count");
  const seen = new Set<string>();
  const times: Date[] = [];
  for (const entry of entries) {
    object(entry);
    const keyID = nonempty(entry.logId?.keyId);
    const id = keyID + ":" + integer(entry.logIndex, "log index");
    if (seen.has(id)) throw new Error("Duplicate transparency receipt");
    seen.add(id);
    const time = integer(entry.integratedTime, "integrated time");
    const at = new Date(Number(time) * 1000);
    if (!Number.isFinite(at.getTime()))
      throw new Error("Invalid observer time");
    const log = root.tlogs.find(
      (l) =>
        l.logId.keyId === keyID &&
        (!time || inWindow(at, l.publicKey.validFor)),
    );
    if (!log) throw new Error("Unknown transparency log");
    await bodyBinding(entry, b, signer, certificate);
    await verifyMerkle(entry, log);
    if (entry.inclusionPromise !== undefined) {
      const sig = unbase64(
        nonempty(entry.inclusionPromise.signedEntryTimestamp),
      );
      const signed = utf8(
        canonicalJSON({
          body: entry.canonicalizedBody,
          integratedTime: Number(time),
          logIndex: Number(integer(entry.logIndex, "log index")),
          logID: hex(unbase64(keyID)),
        }),
      );
      if (!(await verifySignature(await logKey(log), signed, sig)))
        throw new Error("Invalid signed entry timestamp");
      if (time > 0n) times.push(at);
    }
  }
  return times;
}
export interface VerifiedStatement {
  statement: any;
  certificate: X509Certificate;
  payload: Uint8Array;
  tlogTimes: Date[];
}
export async function verifyStatement(
  value: unknown,
  identity: RegExp,
  digest: string,
  root: SigstoreRoot = productionRoot,
  subjectName?: string,
): Promise<VerifiedStatement> {
  unhex(digest, 32, false);
  const b = parseBundle(value),
    vm = b.vm;
  if (!vm.certificate || vm.publicKey !== undefined)
    throw new Error("A single signing certificate is required");
  const der = unbase64(nonempty(vm.certificate.rawBytes));
  const cert = checkedCertificate(der);
  keyPurpose(cert, "1.3.6.1.5.5.7.3.3");
  if (!identity.test(cert.subjectAltName ?? ""))
    throw new Error("Untrusted workflow identity");
  if (
    (cert.extFulcioIssuerV2?.issuer ?? cert.extFulcioIssuerV1?.issuer) !==
    "https://token.actions.githubusercontent.com"
  )
    throw new Error("Untrusted OIDC issuer");
  if (cert.extRunnerEnvironment?.runnerEnvironment !== "github-hosted")
    throw new Error("Workflow runner must be github-hosted");
  const tlogTimes = await verifyLogEntries(b, root, der, true);
  const timestamps = await verifyBundleTimestamp(
    vm.timestampVerificationData,
    b.signature,
    root.timestampAuthorities,
  );
  const observerTimes = [
    ...tlogTimes,
    ...timestamps.map(({ signingTime }) => signingTime),
  ];
  if (!observerTimes.length)
    throw new Error("No authenticated observer timestamp");
  const verifier = new SigstoreVerifier();
  const cas = root.certificateAuthorities.map((c) => ({
    certChain: c.certChain.certificates.map((x) =>
      checkedCertificate(unbase64(x.rawBytes)),
    ),
    validFor: {
      start: new Date(c.validFor.start),
      end: new Date("end" in c.validFor ? c.validFor.end! : 8640000000000000),
    },
  }));
  // Every authenticated observer must fall inside the complete chain's trust
  // window, including CA retirement; a valid leaf alone is insufficient.
  let path: X509Certificate[] = [];
  for (const at of observerTimes)
    path = await verifier.verifyCertificateChain(at, cert, cas);
  const ctlogs = await Promise.all(
    root.ctlogs.map(async (l) => ({
      logID: unbase64(l.logId.keyId),
      publicKey: await logKey(l),
      operator: l.operator ?? "",
      validFor: {
        start: new Date(l.publicKey.validFor.start),
        end: new Date(
          "end" in l.publicKey.validFor
            ? l.publicKey.validFor.end!
            : 8640000000000000,
        ),
      },
    })),
  );
  if ((await verifier.verifySCT(cert, path[1] ?? path[0], ctlogs)).size < 1)
    throw new Error("Missing authenticated SCT");
  if (
    !(await verifySignature(
      await cert.publicKeyObj,
      pae(b.payload),
      b.signature,
    ))
  )
    throw new Error("Invalid DSSE signature");
  if (subjectName) {
    const found = b.statement.subject.filter(
      (s: any) => s.name === subjectName,
    );
    if (
      found.length !== 1 ||
      String(found[0].digest.sha256).toLowerCase() !== digest.toLowerCase()
    )
      throw new Error("Manifest subject mismatch");
  } else if (
    String(b.statement.subject[0].digest.sha256).toLowerCase() !==
    digest.toLowerCase()
  )
    throw new Error("First artifact subject digest mismatch");
  return {
    statement: b.statement,
    certificate: cert,
    payload: b.payload,
    tlogTimes,
  };
}
/** Check RFC3161 profile before delegating certificate and CMS signature authentication. */
export async function verifyInnerTimestamp(
  response: Uint8Array,
  input: Uint8Array,
  root: SigstoreRoot,
): Promise<Date> {
  if (!response.length || response.length > 65536)
    throw new Error("Timestamp size outside bounds");
  const a = strictDER(response);
  if (
    !equal(a.toDER(), response) ||
    ![0n, 1n].includes(a.subs[0].subs[0].toInteger())
  )
    throw new Error("Invalid timestamp response");
  const signed = a.subs[1].subs[1].subs[0];
  const enc = signed.subs[2];
  const oct = enc.subs[1].subs[0];
  const tst = oct.subs[0] ?? ASN1Obj.parseBuffer(oct.value);
  if (
    tst.subs[0].toInteger() !== 1n ||
    tst.subs[1].toOID() !== "1.3.6.1.4.1.57264.2" ||
    tst.subs[2].subs[0].subs[0].toOID() !== "2.16.840.1.101.3.4.2.1" ||
    !equal(tst.subs[2].subs[1].value, await sha256(input))
  )
    throw new Error("Timestamp policy or imprint mismatch");
  const signerInfos = signed.subs[signed.subs.length - 1];
  if (signerInfos.subs.length !== 1)
    throw new Error("Timestamp must have one signer");
  const attrs = signerInfos.subs[0].subs.find((x) =>
    x.tag.isContextSpecific(0),
  );
  if (!attrs) throw new Error("Timestamp signed attributes required");
  const seen = new Set<string>();
  for (const attr of attrs.subs) {
    const oid = attr.subs[0].toOID();
    if (seen.has(oid)) throw new Error("Duplicate timestamp signed attribute");
    seen.add(oid);
  }
  const contentType = attrs.subs.find(
    (x) => x.subs[0].toOID() === "1.2.840.113549.1.9.3",
  );
  if (
    contentType?.subs[1].subs.length !== 1 ||
    contentType.subs[1].subs[0].toOID() !== "1.2.840.113549.1.9.16.1.4"
  )
    throw new Error("Timestamp signed content type mismatch");
  for (const ca of root.timestampAuthorities) {
    if (ca.certChain.certificates.length)
      keyPurpose(
        checkedCertificate(unbase64(ca.certChain.certificates[0].rawBytes)),
        "1.3.6.1.5.5.7.3.8",
        true,
      );
  }
  const times = await verifyBundleTimestamp(
    { rfc3161Timestamps: [{ signedTimestamp: base64(response) }] },
    input,
    root.timestampAuthorities,
  );
  if (times.length !== 1) throw new Error("No trusted timestamp authority");
  return times[0].signingTime;
}
