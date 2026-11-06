/** The user cache secret store in a browser: nothing persists, so resolution uses a secret kept for the page's life. */
export function loadOrPersistUserCacheSecret(_generate: () => string): string | null {
  return null;
}
