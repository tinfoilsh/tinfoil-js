/**
 * Browser build of the user-cache-secret store. Browsers have no filesystem
 * to persist the secret in, so resolution attempts a process-lifetime
 * in-memory secret.
 */

export function loadOrPersistUserCacheSecret(_generateSecret: () => string): string | null {
  return null;
}
