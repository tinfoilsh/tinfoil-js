/** Every declaration file reachable from `entries`, entries included, as absolute paths. */
export function reachableDeclarations(entries: readonly string[]): Set<string>;
/** Every `.d.ts` under `dir`, as absolute paths. */
export function declarationsUnder(dir: string): string[];
