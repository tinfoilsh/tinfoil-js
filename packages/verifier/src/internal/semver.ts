/**
 * Semantic versions with a leading "v": vMAJOR.MINOR.PATCH, optionally
 * followed by "-prerelease" and "+build" metadata. MINOR and PATCH may be
 * omitted ("v1", "v1.2") and canonicalize to 0.
 */

interface Parsed {
  major: string;
  minor: string;
  patch: string;
  /** ".0.0" or ".0" when MINOR or PATCH was omitted ("v1", "v1.2"). */
  short: string;
  prerelease: string;
  build: string;
}

export function isValid(v: string): boolean {
  return parse(v) !== undefined;
}

/** The canonical form: vMAJOR.MINOR.PATCH[-pre], build metadata dropped; "" if invalid. */
export function canonical(v: string): string {
  const p = parse(v);
  if (p === undefined) return "";
  if (p.build !== "") return v.slice(0, v.length - p.build.length);
  if (p.short !== "") return v + p.short;
  return v;
}

/** The build-metadata suffix including "+", or "". */
export function build(v: string): string {
  return parse(v)?.build ?? "";
}

/**
 * Orders two versions by semantic version precedence: negative, zero or
 * positive as `v` is below, equal to or above `w`. Build metadata does not
 * count. An invalid version is below every valid one and equal to any other
 * invalid one.
 */
export function compare(v: string, w: string): number {
  const pv = parse(v);
  const pw = parse(w);
  if (pv === undefined || pw === undefined) return pv === pw ? 0 : pv === undefined ? -1 : 1;
  return (
    compareNum(pv.major, pw.major) ||
    compareNum(pv.minor, pw.minor) ||
    compareNum(pv.patch, pw.patch) ||
    comparePrerelease(pv.prerelease, pw.prerelease)
  );
}

// Every accepted character is ASCII, so indexing UTF-16 code units is byte
// indexing.
function parse(v: string): Parsed | undefined {
  if (v === "" || v[0] !== "v") return undefined;
  let r = parseNum(v.slice(1));
  if (r === undefined) return undefined;
  const major = v.slice(1, v.length - r.length);
  v = r;
  if (v === "") return { major, minor: "0", patch: "0", short: ".0.0", prerelease: "", build: "" };
  if (v[0] !== ".") return undefined;
  r = parseNum(v.slice(1));
  if (r === undefined) return undefined;
  const minor = v.slice(1, v.length - r.length);
  v = r;
  if (v === "") return { major, minor, patch: "0", short: ".0", prerelease: "", build: "" };
  if (v[0] !== ".") return undefined;
  r = parseNum(v.slice(1));
  if (r === undefined) return undefined;
  const patch = v.slice(1, v.length - r.length);
  v = r;
  let prerelease = "";
  let build = "";
  if (v[0] === "-") {
    const i = prereleaseEnd(v);
    if (i === undefined) return undefined;
    prerelease = v.slice(0, i);
    v = v.slice(i);
  }
  if (v[0] === "+") {
    const i = buildEnd(v);
    if (i === undefined) return undefined;
    build = v.slice(0, i);
    v = v.slice(i);
  }
  if (v !== "") return undefined;
  return { major, minor, patch, short: "", prerelease, build };
}

/** Consumes a decimal number without leading zeros; returns the rest. */
function parseNum(v: string): string | undefined {
  if (v === "" || !isDigit(v[0]!)) return undefined;
  let i = 1;
  while (i < v.length && isDigit(v[i]!)) i++;
  if (v[0] === "0" && i !== 1) return undefined;
  return v.slice(i);
}

function prereleaseEnd(v: string): number | undefined {
  let i = 1;
  let start = 1;
  while (i < v.length && v[i] !== "+") {
    if (!isIdentChar(v[i]!) && v[i] !== ".") return undefined;
    if (v[i] === ".") {
      if (start === i || isBadNum(v.slice(start, i))) return undefined;
      start = i + 1;
    }
    i++;
  }
  if (start === i || isBadNum(v.slice(start, i))) return undefined;
  return i;
}

function buildEnd(v: string): number | undefined {
  let i = 1;
  let start = 1;
  while (i < v.length) {
    if (!isIdentChar(v[i]!) && v[i] !== ".") return undefined;
    if (v[i] === ".") {
      if (start === i) return undefined;
      start = i + 1;
    }
    i++;
  }
  if (start === i) return undefined;
  return i;
}

function isDigit(c: string): boolean {
  return c >= "0" && c <= "9";
}

function isIdentChar(c: string): boolean {
  return (c >= "A" && c <= "Z") || (c >= "a" && c <= "z") || isDigit(c) || c === "-";
}

/** A numeric identifier with a leading zero. */
function isBadNum(v: string): boolean {
  return /^0[0-9]+$/.test(v);
}

/** Orders two decimal numbers without leading zeros, of any length. */
function compareNum(x: string, y: string): number {
  if (x === y) return 0;
  if (x.length !== y.length) return x.length < y.length ? -1 : 1;
  return x < y ? -1 : 1;
}

/**
 * Orders two pre-release strings ("" or "-a.b.c"): a version without one is
 * above a version with one; identifiers compare left to right, numeric ones
 * by value and below alphanumeric ones, the others in ASCII order; a longer
 * list is above its own prefix.
 */
function comparePrerelease(x: string, y: string): number {
  if (x === y) return 0;
  if (x === "") return 1;
  if (y === "") return -1;
  const xs = x.slice(1).split(".");
  const ys = y.slice(1).split(".");
  for (let i = 0; i < xs.length && i < ys.length; i++) {
    const dx = xs[i]!;
    const dy = ys[i]!;
    if (dx === dy) continue;
    const numX = isNum(dx);
    if (numX !== isNum(dy)) return numX ? -1 : 1;
    if (numX) return compareNum(dx, dy);
    return dx < dy ? -1 : 1;
  }
  return xs.length < ys.length ? -1 : 1;
}

function isNum(v: string): boolean {
  return /^[0-9]+$/.test(v);
}
