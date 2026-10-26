import { fields, hex, object, sha256, string } from "./encoding.js";
import {
  COLLATERALS_V3,
  FORMAT,
  type ParsedDocument,
  type SigstoreReference,
} from "./document.js";
import {
  verifyStatement,
  type SigstoreRoot,
  type VerifiedStatement,
} from "./sigstore.js";
import {
  escapeRegExp,
  freshnessTime,
  parseReference,
  PLATFORM_REPO,
  PLATFORM_V1,
  PLATFORM_V2,
  register,
  workflowIdentity,
  type Reference,
} from "./references.js";
import {
  canonicalVersion,
  parseRuntimeManifest,
  runtimePin,
  type RuntimeManifest,
} from "./runtime.js";
import {
  configName,
  validateConfigPins,
  verifyArtifactApproval,
  verifyConfigApproval,
} from "./approvals.js";
import { UsageError, VerificationError } from "./errors.js";
import { parsePlatformArtifact } from "./policy/index.js";
import type {
  ArtifactVerification,
  ConfigVerification,
  EmbeddedReferences,
  VerifierOptions,
} from "./types.js";
interface AuthenticatedArtifact {
  repo: string;
  tag: string;
  digest: string;
  name: string;
  commit: string;
}
export interface ProvenanceOptions {
  root: SigstoreRoot;
  maxAge: number;
  configKeys: readonly Uint8Array[];
  freshnessKeys: readonly Uint8Array[];
  embedded: EmbeddedReferences;
  authorizer?: VerifierOptions["configAuthorizer"];
  requiresConfig: boolean;
}
export interface VerifiedReferences {
  quote: any;
  artifact: ArtifactVerification;
  config?: ConfigVerification;
  platform?: ArtifactVerification;
  expiresAt?: Date;
}
function artifact(
  v: VerifiedStatement,
  repo: string,
  tag: string,
  digest: string,
  name?: string,
): AuthenticatedArtifact {
  const cert = v.certificate;
  if (
    repo === PLATFORM_REPO &&
    (cert.extSourceRepositoryIdentifier?.sourceRepositoryIdentifier !==
      "902195777" ||
      cert.extSourceRepositoryOwnerIdentifier
        ?.sourceRepositoryOwnerIdentifier !== "168487856")
  )
    throw new Error("Publisher repository IDs do not match");
  const ref = cert.extSourceRepositoryRef?.sourceRepositoryRef ?? "";
  if (!ref.startsWith("refs/tags/") || (tag && ref !== "refs/tags/" + tag))
    throw new Error("Authenticated source tag mismatch");
  const commit = cert.extSourceRepositoryDigest?.sourceRepositoryDigest ?? "";
  if (!/^[0-9a-f]{40}$/.test(commit))
    throw new Error("Invalid authenticated source commit");
  const subject = name ?? v.statement.subject[0].name;
  if (!subject) throw new Error("Artifact subject name is missing");
  return {
    repo,
    tag: ref.slice(10),
    digest: digest.toLowerCase(),
    commit,
    name: subject,
  };
}
function projection(
  a: AuthenticatedArtifact,
  approvalTime?: Date,
): ArtifactVerification {
  return { source: "endorsement", ...a, approvalTime };
}
function expiry(times: (Date | undefined)[], maxAge: number): Date | undefined {
  const values = times.filter((x): x is Date => !!x);
  return values.length
    ? new Date(Math.min(...values.map((t) => t.getTime())) + maxAge)
    : undefined;
}
function required<T>(v: T | undefined, label: string): T {
  if (v === undefined) throw new Error(`Missing ${label} collateral`);
  return v;
}
export async function authenticateCode(
  material: SigstoreReference,
  ref: Reference,
  root: SigstoreRoot,
): Promise<{
  artifact: AuthenticatedArtifact;
  snp: any;
  tdx: any;
  shape: any;
}> {
  const tag = ref.tag || material.tag,
    digest = ref.digest || material.digest;
  const v = await verifyStatement(
    material.bundle,
    workflowIdentity(ref.repo),
    digest,
    root,
  );
  const p = object(v.statement.predicate);
  if (
    v.statement.predicateType !==
    "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
  )
    throw new Error("Unsupported workload predicate");
  const tdx = object(p.tdx_measurement);
  const snp = { type: "sev-snp", launch: register(p.snp_measurement) },
    measurements = {
      type: "tdx",
      rtmr1: register(tdx.rtmr1),
      rtmr2: register(tdx.rtmr2),
    };
  const shape = object(p.vm_shape);
  for (const name of ["cpus", "memory_mb", "gpus", "disks"])
    if (!Number.isSafeInteger(shape[name]) || shape[name] < 0)
      throw new Error("Invalid VM shape");
  return {
    artifact: artifact(v, ref.repo, tag, digest),
    snp,
    tdx: measurements,
    shape,
  };
}
/** @internal Isolated platform provenance stage. */
export async function authenticatePlatform(
  material: SigstoreReference,
  format: string,
  root: SigstoreRoot,
): Promise<{
  artifact: AuthenticatedArtifact;
  policy: ReturnType<typeof parsePlatformArtifact>;
}> {
  if (material.repo !== PLATFORM_REPO)
    throw new Error("Untrusted platform publisher");
  const v = await verifyStatement(
    material.bundle,
    workflowIdentity(
      PLATFORM_REPO,
      "platform-release\\.yml",
      "refs/tags/platform-v[0-9][^@]*",
    ),
    material.digest,
    root,
  );
  if (v.statement.predicateType !== format)
    throw new Error("Platform predicate format mismatch");
  return {
    artifact: artifact(v, material.repo, material.tag, material.digest),
    policy: parsePlatformArtifact(v.statement.predicate, format),
  };
}
async function witness(
  bundle: unknown,
  expected: AuthenticatedArtifact,
  root: SigstoreRoot,
  now: Date,
  maxAge: number,
): Promise<Date> {
  const v = await verifyStatement(
    bundle,
    workflowIdentity(
      "tinfoilsh/freshness-witness",
      "freshness\\.yml",
      "refs/heads/main",
    ),
    expected.digest,
    root,
  );
  const s = v.statement;
  if (s.predicateType !== "https://tinfoil.sh/predicate/freshness-witness/v1")
    throw new Error("Unsupported freshness predicate");
  const p = fields(s.predicate, ["format", "endorses"]),
    e = fields(p.endorses, ["repo", "tag", "commit", "subject"]),
    subject = fields(e.subject, ["name", "digest"]);
  if (
    p.format !== s.predicateType ||
    s.subject.length !== 1 ||
    s.subject[0].name !== expected.name ||
    s.subject[0].digest.sha256 !== expected.digest ||
    e.repo !== expected.repo ||
    e.tag !== expected.tag ||
    e.commit !== expected.commit ||
    subject.name !== expected.name ||
    subject.digest !== "sha256:" + expected.digest
  )
    throw new Error("Freshness witness does not match authenticated artifact");
  if (!v.tlogTimes.length)
    throw new Error(
      "Freshness witness has no verified transparency-log timestamp",
    );
  return freshnessTime(
    new Date(Math.min(...v.tlogTimes.map((d) => d.getTime()))),
    now,
    maxAge,
  );
}
export async function verifyReferences(
  doc: ParsedDocument,
  identity: string,
  now: Date,
  opts: ProvenanceOptions,
): Promise<VerifiedReferences> {
  return doc.collateralFormat === COLLATERALS_V3
    ? configReferences(doc, identity, now, opts)
    : releaseReferences(doc, identity, now, opts);
}
async function releaseReferences(
  doc: ParsedDocument,
  identity: string,
  now: Date,
  opts: ProvenanceOptions,
): Promise<VerifiedReferences> {
  if (opts.requiresConfig)
    throw new Error("Configured trust requires attestation-collaterals/v3");
  const pin = parseReference(identity);
  const code = await authenticateCode(
      required(doc.collateral.code, "code"),
      pin,
      opts.root,
    ),
    p = await authenticatePlatform(
      required(doc.collateral.platform, "platform"),
      PLATFORM_V1,
      opts.root,
    );
  const times: Date[] = [];
  for (const [id, artifact] of [
    ["code-freshness", code.artifact],
    ["platform-freshness", p.artifact],
  ] as const) {
    const f = required(doc.collateral.freshness.get(id), id);
    if (f.format !== FORMAT["sigstore-freshness"])
      throw new Error("Workload release requires Sigstore freshness witnesses");
    times.push(await witness(f.bundle, artifact, opts.root, now, opts.maxAge));
  }
  return {
    quote: {
      kind: "release",
      platformArtifact: p.policy,
      snp: code.snp,
      tdx: code.tdx,
      shape: code.shape,
    },
    artifact: projection(code.artifact),
    expiresAt: expiry(times, opts.maxAge),
  };
}
async function configReferences(
  doc: ParsedDocument,
  identity: string,
  now: Date,
  opts: ProvenanceOptions,
): Promise<VerifiedReferences> {
  if (opts.authorizer && identity)
    throw new UsageError(
      "Config authorizer requires an empty trusted identity",
    );
  let pin: Reference | undefined;
  if (identity || (!opts.embedded.config && !opts.authorizer)) {
    pin = parseReference(identity);
    try {
      validateConfigPins(pin);
    } catch (cause) {
      throw new UsageError("Invalid config reference", { cause });
    }
  }
  let bytes: Uint8Array, config: ConfigVerification;
  if (opts.embedded.config) {
    bytes = opts.embedded.config.bytes;
    const name = opts.embedded.config.name ?? "",
      n = name ? configName(name) : undefined;
    const digest = hex(await sha256(bytes));
    if (
      pin &&
      ((pin.repo && "/" + pin.repo !== n?.identity) ||
        (pin.tag && pin.tag !== n?.revision) ||
        (pin.digest && pin.digest !== digest))
    )
      throw new UsageError("Embedded config does not match caller pins");
    config = {
      source: "embedded",
      name,
      digest,
      reference: "",
      signingKeyHint: "",
    };
  } else {
    const material = required(doc.collateral.config, "config");
    bytes = material.config;
    if (opts.authorizer) {
      if (!bytes.length || bytes.length > 1 << 20)
        throw new Error("Config size outside bounds");
      try {
        await opts.authorizer({
          config: new Uint8Array(bytes),
          reference: material.reference,
          bundle: structuredClone(material.bundle),
        });
      } catch (cause) {
        throw new VerificationError(
          "provenance",
          "Caller policy rejected config",
          { cause },
        );
      }
      config = {
        source: "policy",
        name: "",
        digest: hex(await sha256(bytes)),
        reference: "",
        signingKeyHint: "",
      };
    } else {
      if (!material.bundle)
        throw new Error("Unsigned config requires caller authorization");
      const approved = await verifyConfigApproval(
        bytes,
        material.bundle,
        pin!,
        opts.configKeys,
        opts.root,
        now,
        opts.maxAge,
      );
      if (approved.reference !== material.reference)
        throw new Error("Endorsement reference mismatch");
      config = { source: "endorsement", ...approved };
    }
  }
  const runtime = runtimePin(bytes);
  let manifest: RuntimeManifest, runtimeTrust: ArtifactVerification;
  if (opts.embedded.runtime) {
    manifest = await parseRuntimeManifest(opts.embedded.runtime, runtime);
    runtimeTrust = {
      source: "embedded",
      repo: runtime.repo,
      tag: canonicalVersion(runtime.tag),
      digest: runtime.digest,
      name: "",
      commit: "",
    };
  } else {
    const material = required(doc.collateral.runtime, "runtime");
    if (
      material.repo !== runtime.repo ||
      material.tag !== runtime.tag ||
      material.digest !== runtime.digest
    )
      throw new Error("Runtime collateral does not match config pin");
    manifest = await parseRuntimeManifest(material.manifest, runtime);
    const tag = canonicalVersion(runtime.tag),
      name = `tinfoil-inference-${runtime.tag}-manifest.json`;
    const v = await verifyStatement(
      material.bundle,
      workflowIdentity(
        PLATFORM_REPO,
        "release\\.yml",
        "refs/tags/" + escapeRegExp(tag),
      ),
      runtime.digest,
      opts.root,
      name,
    );
    if (v.statement.predicateType !== "https://slsa.dev/provenance/v1")
      throw new Error("Runtime requires SLSA v1 provenance");
    const a = artifact(v, PLATFORM_REPO, tag, runtime.digest, name);
    const f = required(
      doc.collateral.freshness.get("runtime-freshness"),
      "runtime freshness",
    );
    if (f.format !== FORMAT["artifact-freshness"])
      throw new Error("Runtime requires Tinfoil freshness approval");
    runtimeTrust = projection(
      a,
      await verifyArtifactApproval(
        f.bundle,
        { kind: "runtime", ...a },
        opts.freshnessKeys,
        opts.root,
        now,
        opts.maxAge,
      ),
    );
  }
  let policy: ReturnType<typeof parsePlatformArtifact>,
    platformTrust: ArtifactVerification;
  if (opts.embedded.platform) {
    policy = parsePlatformArtifact(opts.embedded.platform, PLATFORM_V2);
    platformTrust = {
      source: "embedded",
      repo: "",
      tag: "",
      name: "",
      commit: "",
      digest: hex(await sha256(opts.embedded.platform)),
    };
  } else {
    if (doc.collateral.platformCount !== 1)
      throw new Error("Ambiguous config platform collateral");
    const p = await authenticatePlatform(
      required(doc.collateral.configPlatform, "config platform"),
      PLATFORM_V2,
      opts.root,
    );
    policy = p.policy;
    if (p.artifact.name !== "platform-endorsements.json")
      throw new Error("Dedicated config platform artifact required");
    const f = required(
      doc.collateral.freshness.get("platform-freshness"),
      "platform freshness",
    );
    if (f.format !== FORMAT["artifact-freshness"])
      throw new Error("Platform requires Tinfoil freshness approval");
    platformTrust = projection(
      p.artifact,
      await verifyArtifactApproval(
        f.bundle,
        { kind: "platform", ...p.artifact },
        opts.freshnessKeys,
        opts.root,
        now,
        opts.maxAge,
      ),
    );
  }
  return {
    quote: {
      kind: "config",
      platformArtifact: policy,
      snp: manifest.snp,
      tdx: manifest.tdx,
      configHash: config.digest,
    },
    artifact: runtimeTrust,
    config,
    platform: platformTrust,
    expiresAt: expiry(
      [
        config.approvalTime,
        runtimeTrust.approvalTime,
        platformTrust.approvalTime,
      ],
      opts.maxAge,
    ),
  };
}
