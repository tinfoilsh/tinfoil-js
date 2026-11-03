/**
 * Semantic versions with a leading "v": vMAJOR.MINOR.PATCH, optionally
 * followed by "-prerelease" and "+build" metadata. MINOR and PATCH may be
 * omitted ("v1", "v1.2") and canonicalize to 0.
 */

interface Parsed {
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

// Every accepted character is ASCII, so indexing UTF-16 code units is byte
// indexing.
function parse(v: string): Parsed | undefined {
  if (v === "" || v[0] !== "v") return undefined;
  let r = parseNum(v.slice(1));
  if (r === undefined) return undefined;
  v = r;
  if (v === "") return { short: ".0.0", prerelease: "", build: "" };
  if (v[0] !== ".") return undefined;
  r = parseNum(v.slice(1));
  if (r === undefined) return undefined;
  v = r;
  if (v === "") return { short: ".0", prerelease: "", build: "" };
  if (v[0] !== ".") return undefined;
  r = parseNum(v.slice(1));
  if (r === undefined) return undefined;
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
  return { short: "", prerelease, build };
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
