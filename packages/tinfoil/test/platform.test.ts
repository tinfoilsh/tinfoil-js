/**
 * The platform's view of the transport modes on Bun: which Bun is new
 * enough to check a connection before sending over it, and the default and
 * allowed modes that follow from it.
 */
import { describe, expect, it } from "vitest";
import { ConfigurationError } from "../src/errors.js";
import { checkAPIKeyRuntime } from "../src/internal/credential.js";
import { bunOlderThan, checkTransportMode, defaultTransportMode, MIN_BUN_FOR_TLS_MODE, pinsTLS, type RuntimeGlobals } from "../src/internal/platform.js";
import { checkWebSocketCapability } from "../src/internal/websocket.js";

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
    // A version with an unreadable or missing part is not read as its readable parts.
    expect(bunOlderThan("1.4.0", bun("1.4.bad"))).toBe("1.4.bad");
    expect(bunOlderThan("1.4.0", bun("1.4"))).toBe("1.4");
    expect(bunOlderThan("1.4.0", bun("1.4.0.1"))).toBe("1.4.0.1");
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

describe("runtimes that emulate Node", () => {
  const deno: RuntimeGlobals = { process: { versions: { node: "22.0.0" } }, Deno: {} };
  const workers: RuntimeGlobals = { process: { versions: { node: "22.0.0" } }, navigator: { userAgent: "Cloudflare-Workers" } };

  it("pins TLS on Node and Bun only", () => {
    expect(pinsTLS(node)).toBe(true);
    expect(pinsTLS({ ...node, navigator: { userAgent: "Node.js/22" } })).toBe(true);
    expect(pinsTLS(bun(MIN_BUN_FOR_TLS_MODE))).toBe(true);
    expect(pinsTLS({})).toBe(false);
  });

  it.each([
    ["Deno", deno],
    ["Cloudflare Workers", workers],
  ])("gives %s the EHBP default, refuses the TLS mode and a pinned WebSocket, and still takes an API key", (_name, globals) => {
    expect(pinsTLS(globals)).toBe(false);
    expect(defaultTransportMode(globals)).toBe("ehbp");
    expect(() => checkTransportMode("ehbp", globals)).not.toThrow();
    expect(() => checkTransportMode("tls", globals)).toThrow(ConfigurationError);
    expect(() => checkTransportMode("tls", globals)).toThrow(/which this runtime only emulates; use "ehbp"/);
    expect(() => checkWebSocketCapability(globals)).toThrow(/which this runtime only emulates/);
    expect(() => checkAPIKeyRuntime("key", globals)).not.toThrow();
  });
});
