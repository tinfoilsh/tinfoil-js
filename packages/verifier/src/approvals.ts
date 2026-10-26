import { p256 } from "@noble/curves/nist.js";
import { ASN1Obj, verifySignature } from "@freedomofpress/crypto-browser";
import {
  base64,
  canonicalJSON,
  concat,
  equal,
  fields,
  hex,
  object,
  sha256,
  string,
  unbase64,
  unhex,
  utf8,
} from "./encoding.js";
import {
  parseBundle,
  pae,
  verifyInnerTimestamp,
  verifyLogEntries,
  type SigstoreRoot,
} from "./sigstore.js";
import { canonicalVersion, fullVersion } from "./runtime.js";
import { freshnessTime, PLATFORM_REPO, type Reference } from "./references.js";
export const DEFAULT_SIGNING_KEY = unbase64(
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcadRPBdmNf1LPWYcY9AZ2CrrqxsynqzLE7k3kahjPxIM42bgZbze0GnT/EmGqe1w6So5AhmXci8By8Azt8gAhw==",
);
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
  configName("/" + ref.repo + "/" + (ref.tag || "revision"));
  if (ref.digest) unhex(ref.digest, 32);
}
async function approval(
  value: unknown,
  keys: readonly Uint8Array[],
  root: SigstoreRoot,
): Promise<{ statement: any; payload: Uint8Array; hint: string }> {
  const b = parseBundle(value, true);
  if (
    b.payload.length > 131072 ||
    utf8(canonicalJSON(value)).length > 4 * 1024 * 1024
  )
    throw new Error("Approval size outside bounds");
  const hint = string(b.vm.publicKey?.hint);
  if (!hint || b.vm.certificate !== undefined)
    throw new Error("Approval requires trusted public-key hint");
  if (
    b.raw.dsseEnvelope.signatures[0].keyid &&
    b.raw.dsseEnvelope.signatures[0].keyid !== hint
  )
    throw new Error("DSSE key ID does not match hint");
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
  if (!(await verifySignature(key, pae(b.payload), b.signature)))
    throw new Error("Invalid approval DSSE signature");
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
  await verifyLogEntries(b, root, der, false);
  return { statement: b.statement, payload: b.payload, hint };
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
  config: Uint8Array,
  value: unknown,
  ref: Reference,
  keys: readonly Uint8Array[],
  root: SigstoreRoot,
  now: Date,
  maxAge: number,
): Promise<{
  name: string;
  digest: string;
  reference: string;
  signingKeyHint: string;
  approvalTime: Date;
}> {
  if (!config.length || config.length > 1 << 20)
    throw new Error("Config size outside bounds");
  validateConfigPins(ref);
  const b = await approval(value, keys, root),
    s = b.statement;
  if (s.predicateType !== "https://tinfoil.sh/predicate/config-endorsement/v1")
    throw new Error("Unsupported config approval predicate");
  fields(s.predicate, ["freshness"]);
  const subject = singleSubject(s),
    name = configName(subject.name);
  if (
    name.identity !== "/" + ref.repo ||
    (ref.tag && ref.tag !== name.revision) ||
    (ref.digest && ref.digest !== subject.digest)
  )
    throw new Error("Config approval does not match trusted identity");
  if (hex(await sha256(config)) !== subject.digest)
    throw new Error("Config bytes do not match approved digest");
  const approvalTime = await inner(
    s,
    "tinfoil-config-freshness/v1",
    root,
    now,
    maxAge,
  );
  return {
    name: name.name,
    digest: subject.digest,
    reference: "sha256:" + hex(await sha256(pae(b.payload))),
    signingKeyHint: b.hint,
    approvalTime,
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
