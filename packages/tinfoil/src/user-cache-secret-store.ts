import {
  closeSync,
  constants,
  fstatSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { join } from "node:path";

/**
 * Node.js persistence for the user cache secret. The other Tinfoil SDKs use
 * the same file, so one machine gets one cache namespace across tools. The
 * browser build swaps this module for a stub (see package.json's `browser`
 * field) — browsers have no filesystem, so resolution falls back to the
 * process-lifetime in-memory secret.
 */

/** Directory under the home directory holding the secret file (mode 0700). */
export const USER_CACHE_SECRET_DIR_NAME = ".tinfoil";

/** Secret file name under the directory (mode 0600). */
export const USER_CACHE_SECRET_FILE_NAME = "user_cache_secret";

const HAS_POSIX_PERMISSIONS = process.platform !== "win32";

function posixReadFlags(): number {
  return constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
}

function trimPersistenceWhitespace(value: string): string {
  return value.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, "");
}

function isExpectedWindowsPath(
  path: string,
  expectedType: "directory" | "file",
): boolean | undefined {
  try {
    const stats = lstatSync(path);
    if (stats.isSymbolicLink()) {
      return false;
    }
    return expectedType === "directory" ? stats.isDirectory() : stats.isFile();
  } catch (err) {
    return (err as { code?: string } | null)?.code === "ENOENT" ? undefined : false;
  }
}

/** Reads the secret file, distinguishing a missing file from unusable state. */
function readSecretFile(path: string): string | undefined | null {
  let fd: number | undefined;
  try {
    if (!HAS_POSIX_PERMISSIONS) {
      const pathState = isExpectedWindowsPath(path, "file");
      if (pathState !== true) {
        return pathState === undefined ? undefined : null;
      }
    }
    fd = openSync(path, HAS_POSIX_PERMISSIONS ? posixReadFlags() : "r");
    if (HAS_POSIX_PERMISSIONS) {
      if (!fstatSync(fd).isFile()) {
        return null;
      }
    }
    let secret: string;
    try {
      secret = trimPersistenceWhitespace(
        new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(fd)),
      );
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
        // Best-effort cleanup after the read has completed.
      }
    }
  }
}

/**
 * Returns the secret persisted under the user's home directory, generating
 * (via `generateSecret`) and persisting one on first use. Returns null when
 * the home directory is unavailable or unwritable — the caller falls back to
 * a process-lifetime in-memory secret. Never throws.
 */
export function loadOrPersistUserCacheSecret(generateSecret: () => string): string | null {
  let home: string;
  try {
    home = homedir();
  } catch {
    return null;
  }
  if (!home) {
    return null;
  }
  const dir = join(home, USER_CACHE_SECRET_DIR_NAME);
  const path = join(dir, USER_CACHE_SECRET_FILE_NAME);

  try {
    if (!HAS_POSIX_PERMISSIONS && isExpectedWindowsPath(dir, "directory") === false) {
      return null;
    }
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    if (HAS_POSIX_PERMISSIONS) {
      let dirFd: number | undefined;
      try {
        dirFd = openSync(dir, posixReadFlags() | constants.O_DIRECTORY);
        if (!fstatSync(dirFd).isDirectory()) {
          return null;
        }
      } finally {
        if (dirFd !== undefined) {
          closeSync(dirFd);
        }
      }
    } else if (isExpectedWindowsPath(dir, "directory") !== true) {
      return null;
    }
  } catch {
    return null;
  }

  const existing = readSecretFile(path);
  if (existing === null) {
    return null;
  }
  if (existing !== undefined) {
    return existing;
  }

  const secret = generateSecret();
  if (secret === "") {
    // CSPRNG failure (the generator already warned): tenant-wide caching,
    // nothing worth persisting.
    return "";
  }

  const candidatePath = join(
    dir,
    `${USER_CACHE_SECRET_FILE_NAME}.${process.pid}.${randomUUID()}.tmp`,
  );

  try {
    // A complete temporary file is linked directly to the destination.
    // Hard-link creation is atomic, so concurrent first users either win or
    // adopt the complete destination created by another process.
    writeFileSync(candidatePath, secret, { encoding: "utf8", flag: "wx", mode: 0o600 });
    try {
      linkSync(candidatePath, path);
    } catch (err) {
      if ((err as { code?: string } | null)?.code !== "EEXIST") {
        return null;
      }
    }
    const persisted = readSecretFile(path);
    return persisted ?? null;
  } catch {
    return null;
  } finally {
    try {
      unlinkSync(candidatePath);
    } catch {
      // Best-effort cleanup: the candidate is never the persisted file.
    }
  }
}
