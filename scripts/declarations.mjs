/**
 * The declaration files a package publishes: which ones its entry points
 * reach, and the pruning of the rest after a build. `prune-declarations.mjs`
 * is the command over this module; the declarations tests import it.
 */
import { existsSync, lstatSync, readdirSync, readFileSync, unlinkSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";

/** The module specifiers a declaration file imports or re-exports from, in either quote style: `from`, bare `import`, `import()` and `/// <reference path>`. */
export function specifiersOf(source) {
  const found = new Set();
  for (const pattern of [/\bfrom\s+(["'])([^"']+)\1/g, /\bimport\s+(["'])([^"']+)\1/g, /\bimport\((["'])([^"']+)\1\)/g, /<reference\s+path=(["'])([^"']+)\1/g]) {
    for (const match of source.matchAll(pattern)) found.add(match[2]);
  }
  return [...found];
}

/** The declaration file a relative specifier names from `from`, or undefined when it isn't relative. */
function declarationOf(from, specifier) {
  if (!specifier.startsWith(".")) return undefined;
  const base = resolve(dirname(from), specifier);
  const candidates = [base.replace(/\.js$/, ".d.ts"), base.replace(/\.ts$/, ".d.ts"), base, `${base}.d.ts`, join(base, "index.d.ts")];
  const file = candidates.find((c) => c.endsWith(".d.ts") && existsSync(c));
  if (file === undefined) throw new Error(`${from}: cannot resolve ${JSON.stringify(specifier)} to a declaration file`);
  return file;
}

/** Every declaration file reachable from `entries`, entries included, as absolute paths. */
export function reachableDeclarations(entries) {
  const seen = new Set();
  const queue = entries.map((e) => resolve(e));
  while (queue.length > 0) {
    const file = queue.pop();
    if (seen.has(file)) continue;
    if (!existsSync(file)) throw new Error(`entry ${file} does not exist`);
    seen.add(file);
    for (const specifier of specifiersOf(readFileSync(file, "utf8"))) {
      const next = declarationOf(file, specifier);
      if (next !== undefined && !seen.has(next)) queue.push(next);
    }
  }
  return seen;
}

/**
 * Every regular `.d.ts` file under `dir`, as absolute paths whether or not
 * `dir` is one. Symbolic links are not followed and not listed, so that a
 * link under the output directory never leads a prune to a file outside
 * it, and anything else that is not a regular file (a pipe, a socket, a
 * device) is not listed either.
 */
export function declarationsUnder(dir) {
  const root = resolve(dir);
  const out = [];
  for (const name of readdirSync(root)) {
    const path = join(root, name);
    const stat = lstatSync(path);
    if (stat.isDirectory()) out.push(...declarationsUnder(path));
    else if (stat.isFile() && name.endsWith(".d.ts")) out.push(path);
  }
  return out;
}

/** Whether `path` names a regular file itself, not through a link. */
const isRegularFile = (path) => existsSync(path) && lstatSync(path).isFile();

/**
 * Removes every `.d.ts` (and its `.d.ts.map`) under `dist` that `entries`
 * don't reach, and reports the kept files that still carry an `@internal`
 * tag. With `dryRun`, nothing is deleted. Only a regular file strictly
 * inside `dist` is ever unlinked, and `dist` itself must not be a symbolic
 * link, which would lead the prune into the directory that it points at.
 * Paths in the result are absolute.
 */
export function pruneDeclarations(dist, entries, { dryRun = false } = {}) {
  const root = resolve(dist);
  if (lstatSync(root).isSymbolicLink()) throw new Error(`refusing to prune ${root}: the output directory is a symbolic link`);
  const keep = reachableDeclarations(entries);
  const removed = [];
  for (const file of declarationsUnder(root)) {
    if (keep.has(file)) continue;
    if (!file.startsWith(root + sep)) throw new Error(`refusing to remove ${file}: outside ${root}`);
    if (!dryRun) {
      unlinkSync(file);
      if (isRegularFile(`${file}.map`)) unlinkSync(`${file}.map`);
    }
    removed.push(file);
  }
  const kept = [...keep];
  const leaking = kept.filter((file) => readFileSync(file, "utf8").includes("@internal"));
  return { kept, removed, leaking };
}
