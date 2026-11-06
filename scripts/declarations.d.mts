/** The module specifiers a declaration file imports or re-exports from. */
export function specifiersOf(source: string): string[];
/** Every declaration file reachable from `entries`, entries included, as absolute paths. */
export function reachableDeclarations(entries: readonly string[]): Set<string>;
/** Every regular `.d.ts` file under `dir`, as absolute paths; symbolic links and other non-regular files are skipped. */
export function declarationsUnder(dir: string): string[];
/** Removes the declaration files `entries` don't reach (unless `dryRun`) and reports what was kept, removed and still carries `@internal`; refuses a `dist` that is a symbolic link. */
export function pruneDeclarations(
  dist: string,
  entries: readonly string[],
  options?: { readonly dryRun?: boolean },
): { readonly kept: string[]; readonly removed: string[]; readonly leaking: string[] };
