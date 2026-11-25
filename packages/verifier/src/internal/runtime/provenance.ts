/** Reads the container builds that a Tinfoil config requires. */
import { isLowerHex } from "../canonical.js";
import { object, raw, str } from "../json/decode.js";
import { strictParse, type JsonObject, type JsonValue } from "../json/index.js";

/** Precedes the hex SHA-256 digest that ends a pinned image reference. */
const IMAGE_DIGEST_PREFIX = "@sha256:";
const SHA256_HEX_LENGTH = 64;
const GITHUB_MEMBER = "github";
const GITHUB_MEMBERS = ["repository", "repository_id", "workflow", "ref", "commit"];

/**
 * The build that a config requires for the container image with the
 * lowercase hex SHA-256 `digest`: a run of a GitHub Actions workflow of a
 * repository, at the Git ref `ref` and the source commit `commit`.
 */
export interface ContainerProvenance {
  readonly digest: string;
  readonly repository: string;
  readonly repositoryID: string;
  readonly workflow: string;
  readonly ref: string;
  readonly commit: string;
}

/**
 * Returns the builds that a config requires, in container order. A
 * requirement of any shape but the one it reads is an error, so that an
 * unknown kind of requirement is never treated as met. The publisher and
 * guest own validation of the values.
 */
export function configContainerProvenance(config: Uint8Array): ContainerProvenance[] {
  let containers: JsonValue | undefined;
  try {
    containers = raw(object(strictParse(config), "config"), "containers");
  } catch (err) {
    throw new Error(`parsing config containers: ${(err as Error).message}`);
  }
  if (containers === undefined) return [];
  if (!Array.isArray(containers) || !containers.every((container: JsonValue) => container instanceof Map)) {
    throw new Error("config containers must be an array of objects");
  }
  const required: ContainerProvenance[] = [];
  for (const [index, container] of (containers as readonly JsonObject[]).entries()) {
    const provenance = raw(container, "provenance");
    if (provenance === undefined) continue;
    const github = exactly(exactly(provenance, [GITHUB_MEMBER])?.get(GITHUB_MEMBER), GITHUB_MEMBERS);
    const [repository, repositoryID, workflow, ref, commit] = GITHUB_MEMBERS.map((name) => github?.get(name));
    if (typeof repository !== "string" || typeof repositoryID !== "string" || typeof workflow !== "string" || typeof ref !== "string" || typeof commit !== "string") {
      throw new Error(`containers[${index}].provenance must hold only github, with only the strings repository, repository_id, workflow, ref and commit`);
    }
    const image = str(container, "image");
    const split = image.length - SHA256_HEX_LENGTH;
    if (split < 0 || !image.slice(0, split).endsWith(IMAGE_DIGEST_PREFIX) || !isLowerHex(image.slice(split))) {
      throw new Error(`containers[${index}].image must end with ${IMAGE_DIGEST_PREFIX} and a lowercase hex digest`);
    }
    required.push({ digest: image.slice(split), repository, repositoryID, workflow, ref, commit });
  }
  return required;
}

/** Returns `value` when it is an object with exactly the members `names`. */
function exactly(value: JsonValue | undefined, names: readonly string[]): JsonObject | undefined {
  return value instanceof Map && value.size === names.length && names.every((name) => value.has(name)) ? value : undefined;
}
