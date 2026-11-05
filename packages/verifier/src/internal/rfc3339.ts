/** RFC 3339 timestamps as collateral states them. */

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

/**
 * Parses an RFC 3339 timestamp: 'T' and 'Z' uppercase, optional fractional
 * seconds, 'Z' or a numeric offset. The calendar date must exist and the
 * clock fields must be in range. `what` names the field in errors.
 */
export function parseRfc3339(s: string, what: string): Date {
  const m = RFC3339.exec(s);
  const d = new Date(s);
  if (m === null || Number.isNaN(d.getTime())) throw new Error(`${what} ${JSON.stringify(s)} is not RFC 3339`);
  const [year, month, day, hour, minute, second] = m.slice(1, 7).map(Number);
  // A Date rolls an impossible day into the next month; a real date reads
  // back unchanged. The year is set explicitly because the constructor
  // remaps two-digit years.
  const probe = new Date(0);
  probe.setUTCFullYear(year, month - 1, day);
  if (probe.getUTCFullYear() !== year || probe.getUTCMonth() !== month - 1 || probe.getUTCDate() !== day || hour > 23 || minute > 59 || second > 59) {
    throw new Error(`${what} ${JSON.stringify(s)} is not a real time`);
  }
  return d;
}
