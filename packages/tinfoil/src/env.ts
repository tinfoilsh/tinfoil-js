export function isBun(): boolean {
  return typeof process !== "undefined" &&
    !!(process as any).versions &&
    !!(process as any).versions.bun;
}

/**
 * Detects if the code is running in a real browser environment.
 * Returns false for server-side runtimes (Node.js, Bun, Deno, edge runtimes).
 * Only returns true when we can positively identify a browser environment.
 */
export function isRealBrowser(): boolean {
  // Check for Node.js
  if (
    typeof process !== "undefined" &&
    (process as any).versions &&
    (process as any).versions.node
  ) {
    return false;
  }

  // Check for Bun
  if (isBun()) {
    return false;
  }

  // Check for Deno
  if (typeof (globalThis as any).Deno !== "undefined") {
    return false;
  }

  // Check for Cloudflare Workers (has 'Cloudflare-Workers' userAgent when global_navigator flag is set)
  if (typeof navigator !== "undefined" && navigator.userAgent === "Cloudflare-Workers") {
    return false;
  }

  // Check for Cloudflare Workers via caches.default (alternative detection)
  if (typeof caches !== "undefined" && (caches as any).default !== undefined) {
    return false;
  }

  // Check for real browser: must have window, document, and a real userAgent
  if (typeof window !== "undefined" && typeof window.document !== "undefined") {
    if (typeof navigator !== "undefined" && navigator.userAgent) {
      return true;
    }
  }

  // Unknown runtime - treat as server-side (safer default)
  return false;
}


