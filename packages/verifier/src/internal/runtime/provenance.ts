/** Reads the container build requirements from a Tinfoil config. */
import { isAlias, isMap, isScalar, isSeq, parseAllDocuments, Scalar, visit, type Document, type YAMLMap } from "yaml";
import { REPO_NAME_RE } from "../endorsement/reference.js";

const PARSE_ERROR = "parsing config provenance";
const PROVENANCE_FIELD = "provenance";
const GITHUB_FIELD = "github";
const GITHUB_FIELDS = ["repository", "repository_id", "workflow", "ref"];
const MERGE_KEY = "<<";

// A signing identity is matched against these values, so their length
// bounds that work.
const MAX_GITHUB_REPOSITORY_LENGTH = 140;
const MAX_GITHUB_WORKFLOW_LENGTH = 255;
const MAX_GITHUB_REF_LENGTH = 255;
/** The largest repository ID, the signed 64-bit maximum, in decimal. */
const MAX_REPOSITORY_ID = "9223372036854775807";

const GITHUB_WORKFLOW_RE = /^[A-Za-z0-9_.-]+\.ya?ml$/;
const GITHUB_REF_RE = /^refs\/(?:tags|heads)\/[A-Za-z0-9_.*-]+(?:\/[A-Za-z0-9_.*-]+)*$/;
const REPOSITORY_ID_RE = /^[1-9][0-9]*$/;
const IMAGE_DIGEST_RE = /^[^@\t\n\f\r ]+@sha256:([0-9a-f]{64})$/;

/**
 * The build a config requires for one container image: a GitHub Actions
 * workflow run in a named repository. `ref` is a tag or branch ref pattern
 * in which "*" matches any run of characters other than "/" and "@".
 */
export interface ContainerProvenance {
  readonly container: string;
  /** Lowercase hex SHA-256 of the image. */
  readonly digest: string;
  readonly repository: string;
  /** The repository's numeric ID, in decimal. */
  readonly repositoryID: string;
  readonly workflow: string;
  readonly ref: string;
}

/** The part of a requirement that names the build. */
type GitHubProvenance = Omit<ContainerProvenance, "container" | "digest">;

/** The node each alias of a document stands for. */
type Aliases = ReadonlyMap<unknown, unknown>;

/**
 * Returns the build requirements a config declares, in container order. It
 * rejects a requirement it cannot read in full, so a verifier never treats
 * an unknown kind of requirement as met. The stream must hold exactly one
 * document. The root mapping and every container entry must have unique,
 * untagged scalar keys and no merge key: any other key could supply a
 * requirement that this reader does not see.
 */
export function configContainerProvenance(config: Uint8Array): ContainerProvenance[] {
  const doc = parseConfig(config);
  const aliases = aliasesOf(doc);
  const root = resolveAlias(aliases, doc.contents);
  if (isNull(root)) return [];
  if (!isMap(root)) throw new Error(`${PARSE_ERROR}: config is not a mapping`);
  const containers = resolveAlias(aliases, fieldsOf(root, "config").get("containers"));
  if (isNull(containers)) return [];
  if (!isSeq(containers)) throw new Error(`${PARSE_ERROR}: containers must be a sequence`);

  const requirements: ContainerProvenance[] = [];
  containers.items.forEach((item, index) => {
    const path = `containers[${index}]`;
    const entry = resolveAlias(aliases, item);
    if (isNull(entry)) return;
    if (!isMap(entry)) throw new Error(`${PARSE_ERROR}: ${path} must be a mapping`);
    const fields = fieldsOf(entry, path);
    const container = scalarText(aliases, fields.get("name"), `${PARSE_ERROR}: ${path}.name`);
    const image = scalarText(aliases, fields.get("image"), `${PARSE_ERROR}: ${path}.image`);
    const provenance = resolveAlias(aliases, fields.get(PROVENANCE_FIELD));
    if (isNull(provenance)) return;
    const github = githubProvenance(aliases, provenance, `${path}.${PROVENANCE_FIELD}`);
    const digest = IMAGE_DIGEST_RE.exec(image);
    if (digest === null) throw new Error(`${path}.image must pin a SHA-256 digest to declare provenance`);
    requirements.push({ container, digest: digest[1]!, ...github });
  });
  return requirements;
}

/** The single document of the config; a syntax error, an empty stream or a second document rejects. */
function parseConfig(config: Uint8Array): Document.Parsed {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(config);
  } catch {
    throw new Error(`${PARSE_ERROR}: config is not valid UTF-8`);
  }
  // Duplicate keys are judged where the requirements are read, so that a
  // repeated requirement field is reported by its path.
  const docs = parsing(() => parseAllDocuments(text, { uniqueKeys: false }));
  if (!Array.isArray(docs) || docs.length === 0) throw new Error(`${PARSE_ERROR}: EOF`);
  if (docs.length !== 1) throw new Error("config must contain exactly one YAML document");
  const doc = docs[0]!;
  if (doc.errors.length > 0) throw new Error(`${PARSE_ERROR}: ${doc.errors[0]!.message}`);
  return doc;
}

/** Reads the requirement at `path`, the provenance member of a container entry. */
function githubProvenance(aliases: Aliases, node: unknown, path: string): GitHubProvenance {
  const provenance = knownFieldsOf(node, path, [GITHUB_FIELD]);
  const githubPath = `${path}.${GITHUB_FIELD}`;
  if (!provenance.has(GITHUB_FIELD)) throw new Error(`${githubPath} is required`);
  const github = knownFieldsOf(resolveAlias(aliases, provenance.get(GITHUB_FIELD)), githubPath, GITHUB_FIELDS);
  const repository = scalarText(aliases, github.get("repository"), `${githubPath}.repository`);
  const repositoryID = repositoryIDOf(resolveAlias(aliases, github.get("repository_id")));
  const workflow = scalarText(aliases, github.get("workflow"), `${githubPath}.workflow`);
  const ref = scalarText(aliases, github.get("ref"), `${githubPath}.ref`);
  if (repository.length > MAX_GITHUB_REPOSITORY_LENGTH || !REPO_NAME_RE.test(repository)) {
    throw new Error(`${githubPath}.repository ${JSON.stringify(repository)} must be owner/name`);
  }
  if (repositoryID === undefined) throw new Error(`${githubPath}.repository_id must be the repository's numeric ID`);
  if (workflow.length > MAX_GITHUB_WORKFLOW_LENGTH || !GITHUB_WORKFLOW_RE.test(workflow)) {
    throw new Error(`${githubPath}.workflow ${JSON.stringify(workflow)} must be a workflow file name`);
  }
  if (ref.length > MAX_GITHUB_REF_LENGTH || !GITHUB_REF_RE.test(ref)) {
    throw new Error(`${githubPath}.ref ${JSON.stringify(ref)} must be a tag or branch ref pattern`);
  }
  return { repository, repositoryID, workflow, ref };
}

/**
 * The decimal text of a repository ID: an unquoted, untagged scalar written
 * as a positive decimal integer without sign or leading zeros, within the
 * signed 64-bit range. Anything else is undefined, so that the ID compared
 * with a certificate is exactly the text the config shows.
 */
function repositoryIDOf(node: unknown): string | undefined {
  if (!isScalar(node) || node.type !== Scalar.PLAIN || node.tag !== undefined) return undefined;
  const text = node.source;
  if (text === undefined || !REPOSITORY_ID_RE.test(text)) return undefined;
  // Decimals without leading zeros order by length, then as text.
  if (text.length > MAX_REPOSITORY_ID.length || (text.length === MAX_REPOSITORY_ID.length && text > MAX_REPOSITORY_ID)) return undefined;
  return text;
}

/**
 * The values of a mapping that is read as a record, by key. Every key must
 * be an untagged scalar that appears once, and none may be a merge key.
 */
function fieldsOf(map: YAMLMap, name: string): Map<string, unknown> {
  const fields = new Map<string, unknown>();
  for (const pair of map.items) {
    const field = keyText(pair.key);
    if (field === undefined) throw new Error(`${PARSE_ERROR}: ${name} has a key that is not an untagged scalar`);
    if (field === MERGE_KEY) throw new Error(`${PARSE_ERROR}: ${name} has a merge key, which is not supported`);
    if (fields.has(field)) throw new Error(`${PARSE_ERROR}: ${name} mapping key ${JSON.stringify(field)} already defined`);
    fields.set(field, pair.value);
  }
  return fields;
}

/** The values of a requirement mapping by key; a key outside `allowed`, a repeated key or a non-mapping rejects. */
function knownFieldsOf(node: unknown, name: string, allowed: readonly string[]): Map<string, unknown> {
  if (!isMap(node)) throw new Error(`${name} must be a mapping`);
  const fields = new Map<string, unknown>();
  for (const pair of node.items) {
    const field = keyText(pair.key) ?? "";
    if (fields.has(field)) throw new Error(`${name} has duplicate field ${JSON.stringify(field)}`);
    if (!allowed.includes(field)) throw new Error(`${name} has unknown field ${JSON.stringify(field)}`);
    fields.set(field, pair.value);
  }
  return fields;
}

/** The text of an untagged scalar key; undefined for any other key, whose reading is not the text the config shows. */
function keyText(key: unknown): string | undefined {
  return isScalar(key) && key.tag === undefined ? key.source : undefined;
}

/** The text of the scalar value called `name`: any scalar reads as its text, and an absent or null value is "". */
function scalarText(aliases: Aliases, value: unknown, name: string): string {
  const node = resolveAlias(aliases, value);
  if (isNull(node)) return "";
  if (!isScalar(node)) throw new Error(`${name} must be a scalar`);
  return node.source ?? String(node.value);
}

function isNull(node: unknown): boolean {
  return node === undefined || node === null || (isScalar(node) && node.value === null);
}

/** An alias reads as its anchored node. */
function resolveAlias(aliases: Aliases, node: unknown): unknown {
  if (!isAlias(node)) return node;
  const target = aliases.get(node);
  if (target === undefined) throw new Error(`${PARSE_ERROR}: unknown anchor ${JSON.stringify(node.source)} referenced`);
  return target;
}

/**
 * Resolves every alias of the document in one pass: an alias stands for the
 * last node anchored under its name before it, and one that names no such
 * anchor rejects, wherever it is.
 */
function aliasesOf(doc: Document.Parsed): Aliases {
  const anchored = new Map<string, unknown>();
  const aliases = new Map<unknown, unknown>();
  parsing(() =>
    visit(doc, {
      Node(_key, node) {
        if (!isAlias(node)) {
          if (node.anchor !== undefined) anchored.set(node.anchor, node);
          return;
        }
        const target = anchored.get(node.source);
        if (target === undefined) throw new Error(`unknown anchor ${JSON.stringify(node.source)} referenced`);
        aliases.set(node, target);
      },
    }),
  );
  return aliases;
}

/** Runs a YAML library call; whatever it throws is a parse failure. */
function parsing<T>(read: () => T): T {
  try {
    return read();
  } catch (err) {
    throw new Error(`${PARSE_ERROR}: ${err instanceof Error ? err.message : String(err)}`);
  }
}
