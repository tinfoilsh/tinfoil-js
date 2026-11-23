/** Reads the container build requirements from a Tinfoil config. */
import { isAlias, isMap, isScalar, isSeq, parseAllDocuments, Scalar, visit, type Document, type YAMLMap } from "yaml";
import { REPO_NAME_RE } from "../endorsement/reference.js";

const PARSE_ERROR = "parsing config provenance";
const CONTAINERS_FIELD = "containers";
const NAME_FIELD = "name";
const IMAGE_FIELD = "image";
const PROVENANCE_FIELD = "provenance";
/** The fields this reader takes from the root mapping and from a container entry. */
const RECORD_FIELDS = [CONTAINERS_FIELD, NAME_FIELD, IMAGE_FIELD, PROVENANCE_FIELD];
const GITHUB_FIELD = "github";
const GITHUB_FIELDS = ["repository", "repository_id", "workflow", "ref"];
const MERGE_KEY = "<<";
const YAML_INT_TAG = "tag:yaml.org,2002:int";
const YAML_MAP_TAG = "tag:yaml.org,2002:map";

// A signing identity is matched against these values, so their length
// bounds that work.
const MAX_GITHUB_REPOSITORY_LENGTH = 140;
const MAX_GITHUB_WORKFLOW_LENGTH = 255;
const MAX_GITHUB_REF_LENGTH = 255;

const GITHUB_WORKFLOW_RE = /^[A-Za-z0-9_.-]+\.ya?ml$/;
const GITHUB_REF_RE = /^refs\/(?:tags|heads)\/[A-Za-z0-9_.*-]+(?:\/[A-Za-z0-9_.*-]+)*$/;
// YAML libraries disagree on other spellings of an integer, such as a
// leading zero, so the ID must be written in plain decimal.
const REPOSITORY_ID_RE = /^[1-9][0-9]{0,17}$/;
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

/** The values of some fields of a mapping, by key. */
type Fields = ReadonlyMap<string, unknown>;

/** What reading one config document keeps. */
interface Reading {
  /** The node each alias of the document stands for. */
  readonly aliases: ReadonlyMap<unknown, unknown>;
  /** The record fields of each mapping read so far, with its merge keys resolved. */
  readonly records: Map<YAMLMap, Fields>;
}

/** A mapping whose own keys have been read, and the mappings it merges, of which those from `next` on remain to be read. */
interface Merge {
  readonly map: YAMLMap;
  readonly fields: Map<string, unknown>;
  readonly sources: readonly YAMLMap[];
  next: number;
}

/**
 * Returns the build requirements a config declares, in container order. It
 * rejects a requirement it cannot read in full, so a verifier never treats
 * an unknown kind of requirement as met. The stream must hold exactly one
 * document, which is read with its aliases and merge keys resolved. The root
 * mapping, every container entry and every mapping merged into one must
 * have unique, untagged scalar keys: any other key could supply a
 * requirement that this reader does not see.
 */
export function configContainerProvenance(config: Uint8Array): ContainerProvenance[] {
  const doc = parseConfig(config);
  const reading: Reading = { aliases: aliasesOf(doc), records: new Map() };
  const root = resolveAlias(reading, doc.contents);
  if (isNull(root)) return [];
  if (!isMap(root)) throw new Error(`${PARSE_ERROR}: config is not a mapping`);
  const containers = resolveAlias(reading, recordOf(reading, root, "config").get(CONTAINERS_FIELD));
  if (isNull(containers)) return [];
  if (!isSeq(containers)) throw new Error(`${PARSE_ERROR}: ${CONTAINERS_FIELD} must be a sequence`);

  const requirements: ContainerProvenance[] = [];
  containers.items.forEach((item, index) => {
    const path = `${CONTAINERS_FIELD}[${index}]`;
    const entry = resolveAlias(reading, item);
    if (isNull(entry)) return;
    if (!isMap(entry)) throw new Error(`${PARSE_ERROR}: ${path} must be a mapping`);
    const fields = recordOf(reading, entry, path);
    const container = scalarText(reading, fields.get(NAME_FIELD), `${PARSE_ERROR}: ${path}.${NAME_FIELD}`);
    const image = scalarText(reading, fields.get(IMAGE_FIELD), `${PARSE_ERROR}: ${path}.${IMAGE_FIELD}`);
    const provenance = resolveAlias(reading, fields.get(PROVENANCE_FIELD));
    if (isNull(provenance)) return;
    const github = githubProvenance(reading, provenance, `${path}.${PROVENANCE_FIELD}`);
    const digest = IMAGE_DIGEST_RE.exec(image);
    if (digest === null) throw new Error(`${path}.${IMAGE_FIELD} must pin a SHA-256 digest to declare provenance`);
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
function githubProvenance(reading: Reading, node: unknown, path: string): GitHubProvenance {
  const provenance = knownFieldsOf(node, path, [GITHUB_FIELD]);
  const githubPath = `${path}.${GITHUB_FIELD}`;
  if (!provenance.has(GITHUB_FIELD)) throw new Error(`${githubPath} is required`);
  const github = knownFieldsOf(resolveAlias(reading, provenance.get(GITHUB_FIELD)), githubPath, GITHUB_FIELDS);
  const repository = scalarText(reading, github.get("repository"), `${githubPath}.repository`);
  const repositoryID = repositoryIDOf(resolveAlias(reading, github.get("repository_id")));
  const workflow = scalarText(reading, github.get("workflow"), `${githubPath}.workflow`);
  const ref = scalarText(reading, github.get("ref"), `${githubPath}.ref`);
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
 * The text of a repository ID: an integer scalar, either unquoted and
 * untagged or tagged as an integer, written as a positive decimal of at
 * most 18 digits without sign, leading zero or separator. Anything else is
 * undefined. The ID is the scalar's text, never a number read from it, so
 * that what is compared with a certificate is exactly what the config shows.
 */
function repositoryIDOf(node: unknown): string | undefined {
  if (!isScalar(node)) return undefined;
  const integer = node.tag === undefined ? node.type === Scalar.PLAIN : node.tag === YAML_INT_TAG;
  return integer && node.source !== undefined && REPOSITORY_ID_RE.test(node.source) ? node.source : undefined;
}

/**
 * The record fields of a mapping, with its merge keys resolved: a key of
 * the mapping itself comes before a merged one, and an earlier merged
 * mapping before a later one. In the mapping and in every mapping merged
 * into it, each key must be an untagged scalar that appears once. Every
 * mapping is read once, and a chain of merges is followed without recursion,
 * however long it is.
 */
function recordOf(reading: Reading, map: YAMLMap, name: string): Fields {
  const known = reading.records.get(map);
  if (known !== undefined) return known;
  // The mappings being merged, outermost first; none may merge itself.
  const merges = [ownFields(reading, map, name)];
  const merging = new Set([map]);
  for (;;) {
    const merge = merges[merges.length - 1]!;
    const source = merge.sources[merge.next];
    if (source === undefined) {
      merges.pop();
      merging.delete(merge.map);
      reading.records.set(merge.map, merge.fields);
      if (merges.length === 0) return merge.fields;
      continue;
    }
    const record = reading.records.get(source);
    if (record === undefined) {
      if (merging.has(source)) throw new Error(`${PARSE_ERROR}: ${name} merges a mapping into itself`);
      merging.add(source);
      merges.push(ownFields(reading, source, name));
      continue;
    }
    for (const [key, value] of record) {
      if (!merge.fields.has(key)) merge.fields.set(key, value);
    }
    merge.next++;
  }
}

/** The record fields a mapping holds itself, and the mappings its merge key names. */
function ownFields(reading: Reading, map: YAMLMap, name: string): Merge {
  const fields = new Map<string, unknown>();
  const keys = new Set<string>();
  let sources: YAMLMap[] = [];
  for (const pair of map.items) {
    const key = keyText(pair.key);
    if (key === undefined) throw new Error(`${PARSE_ERROR}: ${name} has a key that is not an untagged scalar`);
    if (keys.has(key)) throw new Error(`${PARSE_ERROR}: ${name} mapping key ${JSON.stringify(key)} already defined`);
    keys.add(key);
    if (isMergeKey(pair.key)) sources = mergeSources(reading, pair.value, name);
    else if (RECORD_FIELDS.includes(key)) fields.set(key, pair.value);
  }
  return { map, fields, sources, next: 0 };
}

/** Whether `key` is a merge key: "<<" written unquoted and untagged. Quoted, it is an ordinary key. */
function isMergeKey(key: unknown): boolean {
  return isScalar(key) && key.type === Scalar.PLAIN && key.tag === undefined && key.source === MERGE_KEY;
}

/** The mappings a merge key's value names: one mapping, or a sequence of them, each written in place or as an alias. */
function mergeSources(reading: Reading, value: unknown, name: string): YAMLMap[] {
  return (isSeq(value) ? value.items : [value]).map((item) => {
    const source = isAlias(item) ? reading.aliases.get(item) : item;
    if (!isMap(source)) throw new Error(`${PARSE_ERROR}: ${name} merges a value that is not a mapping`);
    return source;
  });
}

/**
 * The values of a requirement mapping by key; a key outside `allowed`, a
 * repeated key or a non-mapping rejects. A mapping tagged as anything but a
 * mapping is not one: a null tag, for one, must not make a requirement
 * read as absent.
 */
function knownFieldsOf(node: unknown, name: string, allowed: readonly string[]): Fields {
  if (!isMap(node) || (node.tag !== undefined && node.tag !== YAML_MAP_TAG)) throw new Error(`${name} must be a mapping`);
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
function scalarText(reading: Reading, value: unknown, name: string): string {
  const node = resolveAlias(reading, value);
  if (isNull(node)) return "";
  if (!isScalar(node)) throw new Error(`${name} must be a scalar`);
  return node.source ?? String(node.value);
}

function isNull(node: unknown): boolean {
  return node === undefined || node === null || (isScalar(node) && node.value === null);
}

/** An alias reads as its anchored node. */
function resolveAlias(reading: Reading, node: unknown): unknown {
  if (!isAlias(node)) return node;
  const target = reading.aliases.get(node);
  if (target === undefined) throw new Error(`${PARSE_ERROR}: unknown anchor ${JSON.stringify(node.source)} referenced`);
  return target;
}

/**
 * Resolves every alias of the document in one pass: an alias stands for the
 * last node anchored under its name before it, and one that names no such
 * anchor rejects, wherever it is.
 */
function aliasesOf(doc: Document.Parsed): Map<unknown, unknown> {
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
