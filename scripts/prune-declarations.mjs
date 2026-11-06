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
 * The logic lives in `declarations.mjs`, which the declarations tests share.
 */
import { relative } from "node:path";
import { pruneDeclarations } from "./declarations.mjs";

const [dist, ...entries] = process.argv.slice(2);
if (dist === undefined || entries.length === 0) {
  process.stderr.write("usage: prune-declarations.mjs <dist> <entry.d.ts>...\n");
  process.exit(2);
}
const { kept, removed, leaking } = pruneDeclarations(dist, entries);
if (leaking.length > 0) {
  process.stderr.write(`declarations still carry @internal (is stripInternal on?):\n  ${leaking.map((f) => relative(process.cwd(), f)).join("\n  ")}\n`);
  process.exit(1);
}
process.stdout.write(`${dist}: kept ${kept.length} declaration files, removed ${removed.length}\n`);
