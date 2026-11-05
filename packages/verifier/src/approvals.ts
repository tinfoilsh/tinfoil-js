import { p256 } from "@noble/curves/nist.js";
import { ASN1Obj, verifySignature } from "@freedomofpress/crypto-browser";
import {
  SigstoreVerifier,
  verifyBundleTimestamp,
} from "@freedomofpress/sigstore-browser";
import {
  base64,
  canonicalJSON,
  concat,
  equal,
  fields,
  hex,
  nonempty,
  object,
  sha256,
  string,
  text,
  unbase64,
  unhex,
  utf8,
} from "./encoding.js";
import {
  checkedCertificate,
  parseBundle,
  pae,
  verifyInnerTimestamp,
  verifyLogEntries,
  type ParsedBundle,
  type SigstoreRoot,
} from "./sigstore.js";
import { der as strictDER } from "./quote/crypto.js";
import { canonicalVersion, fullVersion, runtimePin } from "./runtime.js";
import { freshnessTime, PLATFORM_REPO, type Reference } from "./references.js";
export const DEFAULT_SIGNING_KEY = unbase64(
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcadRPBdmNf1LPWYcY9AZ2CrrqxsynqzLE7k3kahjPxIM42bgZbze0GnT/EmGqe1w6So5AhmXci8By8Azt8gAhw==",
);
export const PUBLIC_CONFIG_REGISTRY_ID = "https://registry.tinfoil.sh/scopes/public";
const MAX_CERTIFICATE_SIZE = 16 << 10;
const CERTIFICATE_VALIDITY = 10 * 60 * 1000;
const CERTIFICATE_CLOCK_SKEW = 60 * 1000;
const CODE_SIGNING = "1.3.6.1.5.5.7.3.3";
const ECDSA_SHA256 = "1.2.840.10045.4.3.2";
const MAX_APPROVAL_RECEIPTS = 8;
const REGISTRY_ID =
  /^https:\/\/registry\.tinfoil\.sh\/scopes\/(?:public|[0-9a-f]{32})$/;
export function validateRegistryID(value: unknown): string {
  const registryID = string(value);
  if (!REGISTRY_ID.test(registryID)) throw new Error("Invalid registry ID");
  return registryID;
}
export function validateSigningKey(der: Uint8Array): void {
  if (!(der instanceof Uint8Array))
    throw new Error("Signing key must be DER SPKI bytes");
  const asn = ASN1Obj.parseBuffer(der);
  if (
    !equal(asn.toDER(), der) ||
    asn.subs.length !== 2 ||
    asn.subs[0].subs[0].toOID() !== "1.2.840.10045.2.1" ||
    asn.subs[0].subs[1].toOID() !== "1.2.840.10045.3.1.7" ||
    asn.subs[1].value.length !== 66 ||
    asn.subs[1].value[0] !== 0 ||
    asn.subs[1].value[1] !== 4
  )
    throw new Error("Approval signing key must be ECDSA P-256");
  p256.Point.fromBytes(asn.subs[1].value.subarray(1));
}
export function configName(value: unknown): {
  identity: string;
  revision: string;
  name: string;
} {
  const name = string(value),
    m =
      /^\/([a-z0-9]+(?:-[a-z0-9]+)*)\/([a-z0-9]+(?:-[a-z0-9]+)*)\/([A-Za-z0-9][A-Za-z0-9._-]*)$/.exec(
        name,
      );
  if (!m || m[1].length > 63 || m[2].length > 63 || m[3].length > 128)
    throw new Error("Invalid canonical config name");
  return { name, identity: `/${m[1]}/${m[2]}`, revision: m[3] };
}
export function validateConfigPins(ref: Reference): void {
  if (ref.repo) configName("/" + ref.repo + "/" + (ref.tag || "revision"));
  if (ref.digest) unhex(ref.digest, 32);
}
interface Signer {
  der: Uint8Array;
  hint: string;
  key: CryptoKey;
  registryID?: string;
  signedAt?: Date;
}
async function keySigner(
  b: ParsedBundle,
  keys: readonly Uint8Array[],
): Promise<Signer> {
  const hint = string(b.vm.publicKey?.hint);
  if (!hint || b.vm.certificate !== undefined)
    throw new Error("Approval requires trusted public-key hint");
  if (b.vm.timestampVerificationData?.rfc3161Timestamps?.length)
    throw new Error("Approval must use only signed inner timestamp");
  let der: Uint8Array | undefined;
  for (const k of keys) if (base64(await sha256(k)) === hint) der = k;
  if (!der) throw new Error("Untrusted approval signing key");
  const key = await crypto.subtle.importKey(
    "spki",
    der as BufferSource,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  return { der, hint, key };
}
async function certifiedSigner(
  b: ParsedBundle,
  issuerDER: Uint8Array,
  roots: readonly Uint8Array[],
  root: SigstoreRoot,
): Promise<Signer> {
  const vm = b.vm;
  if (
    !vm.certificate ||
    vm.publicKey !== undefined ||
    vm.timestampVerificationData?.rfc3161Timestamps?.length !== 1
  )
    throw new Error(
      "Scoped approval requires a certificate and one signature timestamp",
    );
  const der = unbase64(nonempty(vm.certificate.rawBytes));
  if (
    der.length > MAX_CERTIFICATE_SIZE ||
    issuerDER.length > MAX_CERTIFICATE_SIZE
  )
    throw new Error("Certificate size outside bounds");
  const cert = checkedCertificate(der),
    issuer = checkedCertificate(issuerDER);
  if (
    !roots.some((k) => equal(k, issuer.publicKey)) ||
    !(await issuer.verify())
  )
    throw new Error("Untrusted registry root");
  const usage = cert.extension("2.5.29.15"),
    purposes = cert.extension("2.5.29.37"),
    san = cert.extension("2.5.29.17"),
    names = san ? strictDER(san.value).subs : [];
  if (
    cert.isCA ||
    !cert.extBasicConstraints ||
    !usage ||
    strictDER(usage.value).toBitString().lastIndexOf(1) !== 0 ||
    !purposes ||
    strictDER(purposes.value)
      .subs.map((x) => x.toOID())
      .join() !== CODE_SIGNING ||
    cert.signatureAlgorithmOid !== ECDSA_SHA256 ||
    cert.notAfter.getTime() - cert.notBefore.getTime() > CERTIFICATE_VALIDITY ||
    cert.notBefore < issuer.notBefore ||
    cert.notAfter > issuer.notAfter ||
    cert.subject.length ||
    cert.extFulcioIssuerV1 ||
    cert.extFulcioIssuerV2 ||
    !san?.critical ||
    names.length !== 1 ||
    !names[0].tag.isContextSpecific(6) ||
    names[0].tag.constructed ||
    roots.some((k) => equal(k, cert.publicKey))
  )
    throw new Error("Invalid config signing certificate profile");
  const registryID = validateRegistryID(text(names[0].value));
  validateSigningKey(cert.publicKey);
  const times = await verifyBundleTimestamp(
    vm.timestampVerificationData,
    b.signature,
    root.timestampAuthorities,
  );
  if (times.length !== 1) throw new Error("No trusted signature timestamp");
  const signedAt = times[0].signingTime;
  await new SigstoreVerifier().verifyCertificateChain(signedAt, cert, [
    {
      certChain: [issuer],
      validFor: { start: issuer.notBefore, end: issuer.notAfter },
    },
  ]);
  return {
    der,
    hint: base64(await sha256(cert.publicKey)),
    key: await cert.publicKeyObj,
    registryID,
    signedAt,
  };
}
async function approval(
  value: unknown,
  keys: readonly Uint8Array[],
  root: SigstoreRoot,
  issuer?: Uint8Array,
): Promise<Signer & { statement: any; payload: Uint8Array }> {
  const b = parseBundle(value, true);
  if (
    b.payload.length > 131072 ||
    utf8(canonicalJSON(value)).length > 4 * 1024 * 1024
  )
    throw new Error("Approval size outside bounds");
  const signer = issuer
    ? await certifiedSigner(b, issuer, keys, root)
    : await keySigner(b, keys);
  const keyID = b.raw.dsseEnvelope.signatures[0].keyid;
  if (issuer && keyID !== undefined && keyID !== "")
    throw new Error("Certified approval requires an empty DSSE key ID");
  if (
    b.raw.dsseEnvelope.signatures[0].keyid &&
    b.raw.dsseEnvelope.signatures[0].keyid !== signer.hint
  )
    throw new Error("DSSE key ID does not match hint");
  if (!(await verifySignature(signer.key, pae(b.payload), b.signature)))
    throw new Error("Invalid approval DSSE signature");
  if (!b.vm.tlogEntries?.length || b.vm.tlogEntries.length > MAX_APPROVAL_RECEIPTS)
    throw new Error("Invalid transparency receipt count");
  for (const e of b.vm.tlogEntries ?? []) {
    if (
      e.kindVersion?.kind !== "hashedrekord" ||
      e.kindVersion?.version !== "0.0.2" ||
      Number(e.integratedTime ?? 0) !== 0 ||
      !e.inclusionProof ||
      e.inclusionPromise !== undefined
    )
      throw new Error("Approval requires Rekor v2 inclusion proofs");
  }
  await verifyLogEntries(b, root, signer.der, !!issuer);
  return { statement: b.statement, payload: b.payload, ...signer };
}
function singleSubject(statement: any): { name: string; digest: string } {
  if (statement.subject.length !== 1)
    throw new Error("Approval requires one subject");
  const s = statement.subject[0];
  if (Object.keys(s.digest).length !== 1)
    throw new Error("Approval requires one digest");
  unhex(s.digest.sha256, 32);
  return { name: string(s.name), digest: s.digest.sha256 };
}
async function inner(
  statement: any,
  domain: string,
  root: SigstoreRoot,
  now: Date,
  maxAge: number,
): Promise<Date> {
  const freshness = fields(statement.predicate.freshness, ["rfc3161Timestamp"]);
  const response = unbase64(freshness.rfc3161Timestamp);
  const predicate = { ...statement.predicate };
  delete predicate.freshness;
  const core = { ...statement, predicate };
  const input = concat(utf8(domain + "\0"), utf8(canonicalJSON(core)));
  return freshnessTime(
    await verifyInnerTimestamp(response, input, root),
    now,
    maxAge,
  );
}
export async function verifyConfigApproval(
  config: Uint8Array | undefined,
  value: unknown,
  ref: Reference,
  keys: readonly Uint8Array[],
  root: SigstoreRoot,
  now: Date,
  maxAge: number,
  registry?: { issuer?: Uint8Array; registryIDs: readonly string[] },
): Promise<{
  name: string;
  digest: string;
  reference: string;
  signingKeyHint: string;
  approvalTime: Date;
  runtime?: Reference;
  registryID?: string;
  signatureTime?: Date;
}> {
  if (config && (!config.length || config.length > 1 << 20))
    throw new Error("Config size outside bounds");
  validateConfigPins(ref);
  const b = await approval(value, keys, root, registry?.issuer),
    s = b.statement;
  const v2 =
    s.predicateType === "https://tinfoil.sh/predicate/config-endorsement/v2";
  if (
    !v2 &&
    s.predicateType !== "https://tinfoil.sh/predicate/config-endorsement/v1"
  )
    throw new Error("Unsupported config approval predicate");
  if (registry && v2 !== !!registry.issuer)
    throw new Error("Registry approvals are certified exactly when v2");
  const p = fields(
    s.predicate,
    v2 ? ["scope", "runtime", "freshness"] : ["freshness"],
  );
  let runtime: Reference | undefined;
  if (v2) {
    const r = fields(p.runtime, ["repo", "tag", "digest"]);
    if (r.repo !== PLATFORM_REPO || fullVersion(r.tag) !== r.tag)
      throw new Error("Invalid approved runtime");
    unhex(r.digest, 32);
    runtime = { repo: r.repo, tag: r.tag, digest: r.digest };
    if (validateRegistryID(p.scope) !== (b.registryID ?? p.scope))
      throw new Error("Certificate registry ID does not match signed registry ID");
  }
  const registryID = b.registryID ?? PUBLIC_CONFIG_REGISTRY_ID;
  if (registry && !registry.registryIDs.includes(registryID))
    throw new Error("Config registry ID is not accepted");
  const subject = singleSubject(s),
    name = configName(subject.name);
  if (
    (ref.repo && name.identity !== "/" + ref.repo) ||
    (ref.tag && ref.tag !== name.revision) ||
    (ref.digest && ref.digest !== subject.digest)
  )
    throw new Error("Config approval does not match trusted identity");
  if (!config && !v2)
    throw new Error("Digest-only config approval requires v2");
  if (config && hex(await sha256(config)) !== subject.digest)
    throw new Error("Config bytes do not match approved digest");
  const pin = config && runtime ? runtimePin(config) : runtime;
  if (pin?.tag !== runtime?.tag || pin?.digest !== runtime?.digest)
    throw new Error("Config runtime does not match approved runtime");
  const approvalTime = await inner(
    s,
    v2 ? "tinfoil-config-freshness/v2" : "tinfoil-config-freshness/v1",
    root,
    now,
    maxAge,
  );
  if (b.signedAt) {
    freshnessTime(b.signedAt, now, maxAge);
    if (approvalTime.getTime() > b.signedAt.getTime() + CERTIFICATE_CLOCK_SKEW)
      throw new Error("Approval timestamp follows signature timestamp");
  }
  return {
    name: name.name,
    digest: subject.digest,
    reference: "sha256:" + hex(await sha256(pae(b.payload))),
    signingKeyHint: b.hint,
    approvalTime,
    runtime,
    registryID: registry ? registryID : undefined,
    signatureTime: b.signedAt,
  };
}
export interface ArtifactIdentity {
  kind: "runtime" | "platform";
  repo: string;
  tag: string;
  name: string;
  digest: string;
}
export function validateArtifactIdentity(a: ArtifactIdentity): void {
  if (a.repo !== PLATFORM_REPO)
    throw new Error("Artifact publisher must be cvmimage");
  unhex(a.digest, 32);
  if (a.kind === "platform") {
    if (
      a.name !== "platform-endorsements.json" ||
      !a.tag.startsWith("platform-") ||
      canonicalVersion(a.tag.slice(9)) !== a.tag.slice(9)
    )
      throw new Error("Invalid platform artifact identity");
  } else {
    if (
      canonicalVersion(a.tag) !== a.tag ||
      !a.name.startsWith("tinfoil-inference-") ||
      !a.name.endsWith("-manifest.json")
    )
      throw new Error("Invalid runtime artifact identity");
    const version = fullVersion(
      a.name.slice("tinfoil-inference-".length, -"-manifest.json".length),
    );
    if (canonicalVersion(version) !== a.tag)
      throw new Error("Runtime subject version mismatch");
  }
}
export async function verifyArtifactApproval(
  value: unknown,
  expected: ArtifactIdentity,
  keys: readonly Uint8Array[],
  root: SigstoreRoot,
  now: Date,
  maxAge: number,
): Promise<Date> {
  validateArtifactIdentity(expected);
  const b = await approval(value, keys, root),
    s = b.statement;
  if (s.predicateType !== "https://tinfoil.sh/predicate/artifact-freshness/v1")
    throw new Error("Unsupported artifact approval predicate");
  const p = fields(s.predicate, ["kind", "repo", "tag", "freshness"]),
    subject = singleSubject(s);
  const actual = {
    kind: p.kind,
    repo: p.repo,
    tag: p.tag,
    name: subject.name,
    digest: subject.digest,
  };
  validateArtifactIdentity(actual);
  for (const k of ["kind", "repo", "tag", "name", "digest"] as const)
    if (actual[k] !== expected[k])
      throw new Error(
        "Artifact approval does not match authenticated artifact",
      );
  return inner(s, "tinfoil-artifact-freshness/v1", root, now, maxAge);
}
