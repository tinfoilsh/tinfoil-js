/**
 * The user cache secret: splicing it into request bodies with every other
 * byte preserved, the bodies and requests left untouched, and resolution
 * from the option, the environment, and the persisted file.
 */
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  injectUserCacheSecret,
  pathEligible,
  resetEphemeralUserCacheSecretForTests,
  resolveUserCacheSecret,
  USER_CACHE_SECRET_ENV,
  withCacheSecret,
} from "../src/internal/cachesecret.js";
import type { Fetch } from "../src/options.js";
import { shapeOf } from "../src/internal/transport/transport.js";

const SECRET = "s3cret";
const FIELD = `"user_cache_secret":"${SECRET}"`;

describe("injectUserCacheSecret", () => {
  it("appends the member and preserves every other byte, including integers beyond double precision and nested objects", () => {
    const raw = '{"seed": 9223372036854775807, "nested": {"a": [1, 2.50, {"b": "}\\""}], "user_cache_secret_x": 1}, "e": 1e400}';
    const injected = injectUserCacheSecret(raw, SECRET);
    expect(injected).toBe(`${raw.slice(0, -1)},${FIELD}}`);
    expect(injected).toContain("9223372036854775807");
  });

  it("injects into empty objects and keeps surrounding whitespace", () => {
    expect(injectUserCacheSecret("{}", SECRET)).toBe(`{${FIELD}}`);
    expect(injectUserCacheSecret(" { }\n", SECRET)).toBe(` { ${FIELD}}\n`);
    expect(injectUserCacheSecret('{"a":1}\n', SECRET)).toBe(`{"a":1,${FIELD}}\n`);
  });

  it("replaces an existing empty string in place and escapes the secret", () => {
    expect(injectUserCacheSecret('{"user_cache_secret": "", "a": 1}', SECRET)).toBe(`{"user_cache_secret": "${SECRET}", "a": 1}`);
    expect(injectUserCacheSecret('{"user\\u005fcache_secret":""}', 'q"\\')).toBe('{"user\\u005fcache_secret":"q\\"\\\\"}');
  });

  it("forwards the original for a field that is non-empty, non-string, or repeated", () => {
    for (const raw of [
      '{"user_cache_secret":"mine"}',
      '{"user_cache_secret":null}',
      '{"user_cache_secret":0}',
      '{"user_cache_secret":{}}',
      '{"user_cache_secret":"","user_cache_secret":""}',
    ]) {
      expect(injectUserCacheSecret(raw, SECRET), raw).toBeNull();
    }
  });

  it("forwards the original for a body that is not one JSON object", () => {
    for (const raw of ["", "not json", "[]", '"s"', "1", "null", "{", '{"a":1}}', '{"a":1} {}', '{"a":1,}', "﻿{}"]) {
      expect(injectUserCacheSecret(raw, SECRET), JSON.stringify(raw)).toBeNull();
    }
  });
});

describe("withCacheSecret", () => {
  const captured: { url: string; body: string | undefined; headers: Headers }[] = [];
  const next: Fetch = async (input, init) => {
    const request = new Request(input, init);
    captured.push({ url: request.url, body: request.body === null ? undefined : await request.text(), headers: request.headers });
    return new Response("ok");
  };
  const send = withCacheSecret(next, SECRET);
  const last = () => captured[captured.length - 1]!;

  it("matches the eligible endpoints by method, body, and path suffix", () => {
    const eligible = (url: string, init?: RequestInit) => pathEligible(shapeOf(url, init));
    expect(eligible("https://e.example/v1/chat/completions", { method: "POST", body: "{}" })).toBe(true);
    expect(eligible("https://e.example/proxy/completions", { method: "POST", body: "{}" })).toBe(true);
    expect(eligible("https://e.example/responses", { method: "POST", body: "{}" })).toBe(true);
    expect(eligible("https://e.example/v1/embeddings", { method: "POST", body: "{}" })).toBe(false);
    expect(eligible("https://e.example/v1/chat/completions", { method: "GET" })).toBe(false);
    expect(eligible("https://e.example/v1/chat/completions", { method: "POST" })).toBe(false);
  });

  it("returns the next fetch for an empty secret", () => {
    expect(withCacheSecret(next, "")).toBe(next);
  });

  it("injects into string, byte, blob, stream, and Request bodies and drops a stale content length", async () => {
    const body = '{"seed":9223372036854775807}';
    const want = `{"seed":9223372036854775807,${FIELD}}`;
    const url = "https://e.example/v1/chat/completions";
    await send(url, { method: "POST", body, headers: { "content-length": String(body.length), "content-type": "application/json" } });
    expect(last().body).toBe(want);
    expect(last().headers.get("content-length")).toBeNull();
    expect(last().headers.get("content-type")).toBe("application/json");
    await send(url, { method: "POST", body: new TextEncoder().encode(body) });
    expect(last().body).toBe(want);
    expect(last().headers.get("content-type")).toBeNull();
    await send(url, { method: "POST", body: new Blob([body], { type: "application/json" }) });
    expect(last().body).toBe(want);
    expect(last().headers.get("content-type")).toBe("application/json");
    await send(url, { method: "POST", body: new Response(body).body, duplex: "half" } as RequestInit);
    expect(last().body).toBe(want);
    const request = new Request(url, { method: "POST", body, headers: { authorization: "Bearer k" } });
    await send(request);
    expect(last().body).toBe(want);
    expect(last().headers.get("authorization")).toBe("Bearer k");
    expect(request.bodyUsed).toBe(false);
  });

  it("forwards ineligible requests and bodies it can't inject into untouched", async () => {
    await send("https://e.example/v1/embeddings", { method: "POST", body: "{}" });
    expect(last().body).toBe("{}");
    await send("https://e.example/v1/chat/completions", { method: "POST", body: "not json" });
    expect(last().body).toBe("not json");
    const bytes = new Uint8Array([0x7b, 0xff, 0x7d]);
    await send("https://e.example/v1/chat/completions", { method: "POST", body: bytes });
    expect(last().body).toBe(new TextDecoder().decode(bytes));
    await send("https://e.example/v1/chat/completions", { method: "POST", body: new Response("[1]").body, duplex: "half" } as RequestInit);
    expect(last().body).toBe("[1]");
    const form = new URLSearchParams({ a: "b" });
    await send("https://e.example/v1/chat/completions", { method: "POST", body: form });
    expect(last().body).toBe("a=b");
    expect(last().headers.get("content-type")).toMatch(/x-www-form-urlencoded/);
  });

  it("forwards a body that carries the caller's own secret", async () => {
    await send("https://e.example/v1/responses", { method: "POST", body: '{"user_cache_secret":"theirs"}' });
    expect(last().body).toBe('{"user_cache_secret":"theirs"}');
  });

  it("stops reading a stream body when the request is aborted and rejects with the reason", async () => {
    const url = "https://e.example/v1/chat/completions";
    const stalled = (onCancel: (reason: unknown) => void) =>
      new ReadableStream<Uint8Array>({
        start: (c) => c.enqueue(new TextEncoder().encode('{"seed":')),
        cancel: onCancel,
      });
    const sent = captured.length;
    const controller = new AbortController();
    let cancelled: unknown;
    const pending = send(url, { method: "POST", body: stalled((reason) => (cancelled = reason)), signal: controller.signal, duplex: "half" } as RequestInit);
    await new Promise((resolve) => setTimeout(resolve, 10));
    const reason = new Error("upload abandoned");
    controller.abort(reason);
    await expect(pending).rejects.toBe(reason);
    expect(cancelled).toBe(reason);
    // A Request's own signal stops the read of its body too.
    const gone = new AbortController();
    const request = new Request(url, { method: "POST", body: stalled(() => {}), signal: gone.signal, duplex: "half" } as RequestInit);
    const waiting = send(request);
    await new Promise((resolve) => setTimeout(resolve, 10));
    gone.abort(new Error("gone"));
    await expect(waiting).rejects.toThrow(/gone/);
    expect(captured).toHaveLength(sent);
    // An init whose signal is null leaves the request without one, as fetch has it, however the Request's own stands.
    const stale = new AbortController();
    stale.abort(new Error("stale"));
    const detached = new Request(url, { method: "POST", body: '{"seed":1}', signal: stale.signal });
    await send(detached, { method: "POST", signal: null });
    expect(last().body).toBe(`{"seed":1,${FIELD}}`);
  });
});

describe("resolveUserCacheSecret", () => {
  let home: string;
  // The home directory is redirected under both names, so the tests never touch the real one.
  const saved = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE, secret: process.env[USER_CACHE_SECRET_ENV] };

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "tinfoil-secret-"));
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    delete process.env[USER_CACHE_SECRET_ENV];
    resetEphemeralUserCacheSecretForTests();
  });

  afterEach(() => {
    for (const name of ["HOME", "USERPROFILE"] as const) {
      if (saved[name] === undefined) delete process.env[name];
      else process.env[name] = saved[name];
    }
    if (saved.secret === undefined) delete process.env[USER_CACHE_SECRET_ENV];
    else process.env[USER_CACHE_SECRET_ENV] = saved.secret;
    rmSync(home, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it("prefers the option, then the environment, then the persisted secret", async () => {
    process.env[USER_CACHE_SECRET_ENV] = "from-env";
    expect(await resolveUserCacheSecret("from-option")).toBe("from-option");
    expect(await resolveUserCacheSecret("")).toBe("from-env");
    expect(await resolveUserCacheSecret(undefined)).toBe("from-env");
    process.env[USER_CACHE_SECRET_ENV] = "";
    const persisted = await resolveUserCacheSecret(undefined);
    expect(persisted).toMatch(/^[0-9a-f]{64}$/);
    expect(readFileSync(join(home, ".tinfoil", "user_cache_secret"), "utf8")).toBe(persisted);
  });

  it("persists a generated secret with private permissions and reuses it", async () => {
    const first = await resolveUserCacheSecret(undefined);
    expect(await resolveUserCacheSecret(undefined)).toBe(first);
    if (process.platform !== "win32") {
      expect(statSync(join(home, ".tinfoil")).mode & 0o777).toBe(0o700);
      expect(statSync(join(home, ".tinfoil", "user_cache_secret")).mode & 0o777).toBe(0o600);
    }
  });

  it("reads a secret another SDK wrote, trimming surrounding whitespace", async () => {
    mkdirSync(join(home, ".tinfoil"), { mode: 0o700 });
    writeFileSync(join(home, ".tinfoil", "user_cache_secret"), "  shared-secret\n", { mode: 0o600 });
    expect(await resolveUserCacheSecret(undefined)).toBe("shared-secret");
  });

  // Creating a symbolic link needs a privilege on Windows that CI runners lack.
  it.skipIf(process.platform === "win32")("falls back to one in-memory secret per process, with a warning, when the file is unusable", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    mkdirSync(join(home, ".tinfoil"), { mode: 0o700 });
    writeFileSync(join(home, "elsewhere"), "planted");
    symlinkSync(join(home, "elsewhere"), join(home, ".tinfoil", "user_cache_secret"));
    const first = await resolveUserCacheSecret(undefined);
    expect(first).toMatch(/^[0-9a-f]{64}$/);
    expect(await resolveUserCacheSecret(undefined)).toBe(first);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(lstatSync(join(home, ".tinfoil", "user_cache_secret")).isSymbolicLink()).toBe(true);
  });

  it("keeps the secret in memory, without a warning, where the runtime isn't a server, such as a worker", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    process.env[USER_CACHE_SECRET_ENV] = "from-env";
    const worker = { self: {}, process: { env: process.env } } as unknown as Parameters<typeof resolveUserCacheSecret>[1];
    const first = await resolveUserCacheSecret(undefined, worker);
    expect(first).toMatch(/^[0-9a-f]{64}$/);
    expect(first).not.toBe("from-env");
    expect(await resolveUserCacheSecret(undefined, worker)).toBe(first);
    expect(existsSync(join(home, ".tinfoil"))).toBe(false);
    expect(warn).not.toHaveBeenCalled();
  });

  it("falls back when the directory can't be created", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    writeFileSync(join(home, ".tinfoil"), "not a directory");
    expect(await resolveUserCacheSecret(undefined)).toMatch(/^[0-9a-f]{64}$/);
  });
});
