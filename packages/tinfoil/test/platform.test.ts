/**
 * The platform's view of the transport modes on Bun: which Bun is new
 * enough to check a connection before sending over it, and the default and
 * allowed modes that follow from it.
 */
import { describe, expect, it } from "vitest";
import { ConfigurationError } from "../src/errors.js";
import { bunOlderThan, checkTransportMode, defaultTransportMode, MIN_BUN_FOR_TLS_MODE, type RuntimeGlobals } from "../src/internal/platform.js";

const bun = (version: string): RuntimeGlobals => ({ process: { versions: { bun: version } } });
const node: RuntimeGlobals = { process: { versions: { node: "22.0.0" } } };

describe("Bun version floors", () => {
  it("orders versions numerically, ignores a canary tag, counts an unreadable version as old, and knows nothing of other runtimes", () => {
    expect(bunOlderThan("1.4.0", bun("1.3.14"))).toBe("1.3.14");
    expect(bunOlderThan("1.4.0", bun("1.4.0"))).toBeUndefined();
    expect(bunOlderThan("1.4.0", bun("1.10.0"))).toBeUndefined();
    expect(bunOlderThan("1.4.4", bun("1.4.3"))).toBe("1.4.3");
    expect(bunOlderThan("1.4.4", bun("1.4.5-canary.20+abc"))).toBeUndefined();
    expect(bunOlderThan("1.4.4", bun("2.0.0"))).toBeUndefined();
    expect(bunOlderThan("1.4.0", bun("unknown"))).toBe("unknown");
    expect(bunOlderThan("1.4.0", node)).toBeUndefined();
    expect(bunOlderThan("1.4.0", {})).toBeUndefined();
  });

  it("gives a Bun too old to check a connection before sending the browser default, and refuses the TLS mode on it by name", () => {
    expect(defaultTransportMode(bun("1.3.14"))).toBe("ehbp");
    expect(defaultTransportMode(bun(MIN_BUN_FOR_TLS_MODE))).toBe("tls");
    expect(defaultTransportMode(node)).toBe("tls");
    expect(() => checkTransportMode("tls", bun("1.3.14"))).toThrow(ConfigurationError);
    expect(() => checkTransportMode("tls", bun("1.3.14"))).toThrow(/Bun 1.3.14 checks only after sending the request; use Bun 1.4.0 or later, or "ehbp"/);
    expect(() => checkTransportMode("ehbp", bun("1.3.14"))).not.toThrow();
    expect(() => checkTransportMode("tls", bun(MIN_BUN_FOR_TLS_MODE))).not.toThrow();
    expect(() => checkTransportMode("tls", node)).not.toThrow();
  });
});
