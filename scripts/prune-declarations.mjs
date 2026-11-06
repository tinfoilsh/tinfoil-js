#!/usr/bin/env node
/**
 * Keeps only the declaration files a package's entry points reach.
 *
 * tsc emits a `.d.ts` for every source file, internal modules included, and
 * the package's `exports` map is all that keeps a consumer from importing
 * them. After a build, this walks the imports of the entry declarations and
 * deletes every other `.d.ts` (and its `.d.ts.map`) under the output
 * directory, so the published types are exactly the reachable ones. It then
 * refuses a kept file that still carries an `@internal` tag, which means
 * `stripInternal` is off or a tag sits where tsc doesn't strip it.
 *
 *   node prune-declarations.mjs <dist> <entry.d.ts>...
 *
 * Entries are relative to the working directory; the walk resolves only
 * relative specifiers, since package imports leave the output directory.
 */
import { existsSync, readdirSync, readFileSync, statSync, unlinkSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";

/** The module specifiers a declaration file imports or re-exports from. */
function specifiersOf(source) {
  const found = new Set();
  for (const pattern of [/\bfrom\s+"([^"]+)"/g, /\bimport\s+"([^"]+)"/g, /\bimport\("([^"]+)"\)/g, /<reference\s+path="([^"]+)"/g]) {
    for (const match of source.matchAll(pattern)) found.add(match[1]);
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

/** Every `.d.ts` under `dir`, as absolute paths. */
export function declarationsUnder(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...declarationsUnder(path));
    else if (name.endsWith(".d.ts")) out.push(path);
  }
  return out;
}

function main(argv) {
  const [dist, ...entries] = argv;
  if (dist === undefined || entries.length === 0) {
    process.stderr.write("usage: prune-declarations.mjs <dist> <entry.d.ts>...\n");
    return 2;
  }
  const root = resolve(dist);
  const keep = reachableDeclarations(entries);
  let removed = 0;
  for (const file of declarationsUnder(root)) {
    if (keep.has(file)) continue;
    unlinkSync(file);
    if (existsSync(`${file}.map`)) unlinkSync(`${file}.map`);
    removed++;
  }
  const leaking = [...keep].filter((file) => readFileSync(file, "utf8").includes("@internal")).map((file) => relative(process.cwd(), file));
  if (leaking.length > 0) {
    process.stderr.write(`declarations still carry @internal (is stripInternal on?):\n  ${leaking.join("\n  ")}\n`);
    return 1;
  }
  process.stdout.write(`${relative(process.cwd(), root)}: kept ${keep.size} declaration files, removed ${removed}\n`);
  return 0;
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === new URL(import.meta.url).pathname) {
  process.exitCode = main(process.argv.slice(2));
}
