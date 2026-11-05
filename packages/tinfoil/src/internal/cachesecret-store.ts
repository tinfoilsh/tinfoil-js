/**
 * Persists the user cache secret under the home directory, where the other
 * Tinfoil SDKs read it too, so one machine gets one cache namespace across
 * tools. Node and Bun only; the browser build maps this module to a stub.
 */
import { randomUUID } from "node:crypto";
import { closeSync, constants, fstatSync, linkSync, lstatSync, mkdirSync, openSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/** The directory under the home directory holding the secret file (mode 0700). */
export const USER_CACHE_SECRET_DIR_NAME = ".tinfoil";
/** The secret file under that directory (mode 0600). */
export const USER_CACHE_SECRET_FILE_NAME = "user_cache_secret";

const POSIX = process.platform !== "win32";

/**
 * The secret persisted under the user's home directory, generating one with
 * `generate` and persisting it on first use. Returns null when the home
 * directory is unavailable or unusable, so the caller falls back to a
 * process-lifetime secret. Never throws.
 */
export function loadOrPersistUserCacheSecret(generate: () => string): string | null {
  let home: string;
  try {
    home = homedir();
  } catch {
    return null;
  }
  if (!home) return null;
  const dir = join(home, USER_CACHE_SECRET_DIR_NAME);
  const path = join(dir, USER_CACHE_SECRET_FILE_NAME);
  try {
    if (!POSIX && expectedPath(dir, "directory") === false) return null;
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    if (POSIX) {
      let fd: number | undefined;
      try {
        fd = openSync(dir, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY);
        if (!fstatSync(fd).isDirectory()) return null;
      } finally {
        if (fd !== undefined) closeSync(fd);
      }
    } else if (expectedPath(dir, "directory") !== true) {
      return null;
    }
  } catch {
    return null;
  }
  const existing = readSecretFile(path);
  if (existing === null) return null;
  if (existing !== undefined) return existing;
  const secret = generate();
  if (secret === "") return "";
  // A complete temporary file is linked to the destination: link creation
  // is atomic, so concurrent first users either win or adopt the winner's.
  const candidate = join(dir, `${USER_CACHE_SECRET_FILE_NAME}.${process.pid}.${randomUUID()}.tmp`);
  try {
    writeFileSync(candidate, secret, { encoding: "utf8", flag: "wx", mode: 0o600 });
    try {
      linkSync(candidate, path);
    } catch (err) {
      if ((err as { code?: string } | null)?.code !== "EEXIST") return null;
    }
    return readSecretFile(path) ?? null;
  } catch {
    return null;
  } finally {
    try {
      unlinkSync(candidate);
    } catch {
      // The candidate is never the persisted file.
    }
  }
}

/** The secret in the file, undefined when the file is missing, null when it is unusable. */
function readSecretFile(path: string): string | undefined | null {
  let fd: number | undefined;
  try {
    if (!POSIX) {
      const state = expectedPath(path, "file");
      if (state !== true) return state === undefined ? undefined : null;
    }
    fd = openSync(path, POSIX ? constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK : "r");
    if (POSIX && !fstatSync(fd).isFile()) return null;
    let secret: string;
    try {
      secret = new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(fd)).replace(/^\p{White_Space}+|\p{White_Space}+$/gu, "");
    } catch {
      return null;
    }
    return secret === "" ? null : secret;
  } catch (err) {
    return (err as { code?: string } | null)?.code === "ENOENT" ? undefined : null;
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        // The read has completed.
      }
    }
  }
}

/** On Windows, where no-follow opens are unavailable: whether `path` is the expected kind and not a link; undefined when absent. */
function expectedPath(path: string, kind: "directory" | "file"): boolean | undefined {
  try {
    const stats = lstatSync(path);
    if (stats.isSymbolicLink()) return false;
    return kind === "directory" ? stats.isDirectory() : stats.isFile();
  } catch (err) {
    return (err as { code?: string } | null)?.code === "ENOENT" ? undefined : false;
  }
}
