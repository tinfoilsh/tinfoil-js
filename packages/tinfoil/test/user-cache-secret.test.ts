import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import OpenAI from "openai";
import { Identity, Transport } from "ehbp";
import {
  USER_CACHE_SECRET_FIELD,
  resolveUserCacheSecret,
  injectUserCacheSecret,
  withUserCacheSecret,
} from "../src/user-cache-secret";
import {
  USER_CACHE_SECRET_DIR_NAME,
  USER_CACHE_SECRET_FILE_NAME,
  loadOrPersistUserCacheSecret,
} from "../src/user-cache-secret-store";
import { createEncryptedBodyFetch } from "../src/encrypted-body-fetch";

const BASE_URL = "https://enclave.example.com/v1/";

/**
 * Points the home directory at `home` for the store's os.homedir() lookup.
 * Both variables are stubbed because homedir() reads HOME on POSIX but
 * USERPROFILE on Windows — stubbing HOME alone would leave a Windows run
 * writing into the developer's real profile.
 */
function stubHome(home: string): void {
  vi.stubEnv("HOME", home);
  vi.stubEnv("USERPROFILE", home);
}

/** Points the home directory at a fresh temp directory and returns it. */
function stubTempHome(): string {
  const home = mkdtempSync(join(tmpdir(), "tinfoil-ucs-"));
  stubHome(home);
  return home;
}

function secretFilePath(home: string): string {
  return join(home, USER_CACHE_SECRET_DIR_NAME, USER_CACHE_SECRET_FILE_NAME);
}

/** A fetch stub that records every call and returns 200 OK. */
function captureFetch() {
  const calls: Array<{ input: RequestInfo | URL; init?: RequestInit }> = [];
  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ input, init });
    return new Response("ok", { status: 200 });
  }) as typeof fetch;
  return { calls, fetch: fetchFn };
}

function postJSON(body: string, extraHeaders: Record<string, string> = {}): RequestInit {
  return {
    method: "POST",
    headers: { "Content-Type": "application/json", ...extraHeaders },
    body,
  };
}

function resolveSecretInChild(
  sourceURL: string,
  home: string,
  generatedSecret: string,
): { ready: Promise<void>; result: Promise<string>; start: () => void } {
  const script = `
    import { loadOrPersistUserCacheSecret } from ${JSON.stringify(sourceURL)};
    process.send("ready");
    await new Promise((resolve) => process.once("message", resolve));
    process.send({ result: loadOrPersistUserCacheSecret(() => ${JSON.stringify(generatedSecret)}) });
    process.disconnect();
  `;
  const child = spawn(
    process.execPath,
    ["--loader", "ts-node/esm", "--input-type=module", "-e", script],
    {
      cwd: fileURLToPath(new URL("..", import.meta.url)),
      env: { ...process.env, HOME: home, USERPROFILE: home },
      stdio: ["ignore", "ignore", "pipe", "ipc"],
    },
  );
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  const ready = new Promise<void>((resolve, reject) => {
    child.once("error", reject);
    child.on("message", (message) => {
      if (message === "ready") {
        resolve();
      }
    });
  });
  const result = new Promise<string>((resolve, reject) => {
    child.once("error", reject);
    child.on("message", (message) => {
      if (typeof message === "object" && message !== null && "result" in message) {
        resolve(String(message.result));
      }
    });
    child.once("exit", (code) => {
      if (code !== 0) {
        reject(new Error(`cache secret child exited with ${code}: ${stderr}`));
      }
    });
  });
  return {
    ready,
    result,
    start: () => child.send("start"),
  };
}

beforeEach(() => {
  // A developer environment may carry the variable; every test controls it
  // explicitly. stubEnv(name, undefined) removes it and registers restoration.
  vi.stubEnv("TINFOIL_USER_CACHE_SECRET", undefined);
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe("resolveUserCacheSecret", () => {
  it("explicit option beats the environment", async () => {
    vi.stubEnv("TINFOIL_USER_CACHE_SECRET", "from-env");
    await expect(resolveUserCacheSecret("explicit")).resolves.toBe("explicit");
  });

  it("treats an explicit empty value as unset", async () => {
    vi.stubEnv("TINFOIL_USER_CACHE_SECRET", "from-env");
    await expect(resolveUserCacheSecret("")).resolves.toBe("from-env");
  });

  it("environment beats generation and touches no file", async () => {
    const home = stubTempHome();
    vi.stubEnv("TINFOIL_USER_CACHE_SECRET", "from-env");

    await expect(resolveUserCacheSecret()).resolves.toBe("from-env");
    expect(
      existsSync(join(home, USER_CACHE_SECRET_DIR_NAME)),
      "an environment-provided secret must not create the secret file",
    ).toBe(false);
  });

  it("treats an empty environment value as unset", async () => {
    const home = stubTempHome();
    vi.stubEnv("TINFOIL_USER_CACHE_SECRET", "");

    await expect(resolveUserCacheSecret()).resolves.toMatch(/^[0-9a-f]{64}$/);
    expect(existsSync(join(home, USER_CACHE_SECRET_DIR_NAME))).toBe(true);
  });

  it("generates a 256-bit hex secret, persists it at 0600, and reuses it", async () => {
    const home = stubTempHome();

    const first = await resolveUserCacheSecret();
    expect(first, "expected a hex-encoded 256-bit secret").toMatch(/^[0-9a-f]{64}$/);

    const path = secretFilePath(home);
    if (process.platform !== "win32") {
      // Windows has no POSIX permission bits; stat reports a synthesized mode.
      expect(statSync(join(home, USER_CACHE_SECRET_DIR_NAME)).mode & 0o777).toBe(0o700);
      expect(statSync(path).mode & 0o777).toBe(0o600);
    }
    expect(readFileSync(path, "utf8")).toBe(first);

    // A second resolution (a new client, or another SDK on the same machine)
    // must reuse the persisted secret, not mint a new namespace.
    await expect(resolveUserCacheSecret()).resolves.toBe(first);
  });

  it("accepts permissive existing state without permission maintenance", async () => {
    const home = stubTempHome();
    const dir = join(home, USER_CACHE_SECRET_DIR_NAME);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    // Trailing newline: the file may be hand-edited or written by another SDK.
    const path = join(dir, USER_CACHE_SECRET_FILE_NAME);
    writeFileSync(path, "shared-secret\n", { mode: 0o600 });
    if (process.platform !== "win32") {
      chmodSync(dir, 0o755);
      chmodSync(path, 0o644);
    }

    await expect(resolveUserCacheSecret()).resolves.toBe("shared-secret");
    if (process.platform !== "win32") {
      expect(statSync(dir).mode & 0o777).toBe(0o755);
      expect(statSync(path).mode & 0o777).toBe(0o644);
    }
  });

  it("keeps a valid destination authoritative", () => {
    const home = stubTempHome();
    const dir = join(home, USER_CACHE_SECRET_DIR_NAME);
    const path = secretFilePath(home);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeFileSync(path, "primary-secret", { mode: 0o600 });

    expect(loadOrPersistUserCacheSecret(() => "must-not-be-used")).toBe("primary-secret");
  });

  it("leaves invalid UTF-8 persistence unchanged and uses a stable process fallback", async () => {
    const home = stubTempHome();
    const dir = join(home, USER_CACHE_SECRET_DIR_NAME);
    const path = secretFilePath(home);
    const corrupted = new Uint8Array([0xff, 0xfe, 0x61]);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeFileSync(path, corrupted, { mode: 0o600 });

    expect(loadOrPersistUserCacheSecret(() => "must-not-be-used")).toBeNull();
    const first = await resolveUserCacheSecret();
    await expect(resolveUserCacheSecret()).resolves.toBe(first);
    expect(first).toMatch(/^[0-9a-f]{64}$/);
    expect(readFileSync(path)).toEqual(Buffer.from(corrupted));
  });

  it("leaves a blank destination unchanged and uses a stable process fallback", async () => {
    const home = stubTempHome();
    const dir = join(home, USER_CACHE_SECRET_DIR_NAME);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const path = join(dir, USER_CACHE_SECRET_FILE_NAME);
    writeFileSync(path, "  \n", { mode: 0o600 });

    const first = await resolveUserCacheSecret();
    await expect(resolveUserCacheSecret()).resolves.toBe(first);
    expect(first).toMatch(/^[0-9a-f]{64}$/);
    expect(readFileSync(path, "utf8")).toBe("  \n");
  });

  it("persists consistently across concurrent processes on first use", async () => {
    const home = stubTempHome();
    const dir = join(home, USER_CACHE_SECRET_DIR_NAME);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const path = secretFilePath(home);
    const sourceURL = new URL("../src/user-cache-secret-store.ts", import.meta.url).href;
    const children = Array.from({ length: 6 }, (_, index) =>
      resolveSecretInChild(sourceURL, home, `child-secret-${index}`),
    );
    await Promise.all(children.map((child) => child.ready));
    children.forEach((child) => child.start());
    const results = await Promise.all(children.map((child) => child.result));

    expect(new Set(results).size).toBe(1);
    expect(readFileSync(path, "utf8")).toBe(results[0]);
    if (process.platform !== "win32") {
      expect(statSync(dir).mode & 0o777).toBe(0o700);
      expect(statSync(path).mode & 0o777).toBe(0o600);
    }
  });

  it.each(["destination", "directory"])(
    "rejects a symlinked %s without changing its target",
    (symlinkKind) => {
      if (process.platform === "win32") {
        return;
      }
      const home = stubTempHome();
      const targetDir = mkdtempSync(join(tmpdir(), "tinfoil-ucs-target-"));
      const targetPath = join(targetDir, "target");
      writeFileSync(targetPath, "target-secret", { mode: 0o644 });
      chmodSync(targetDir, 0o755);

      const dir = join(home, USER_CACHE_SECRET_DIR_NAME);
      const path = secretFilePath(home);
      if (symlinkKind === "directory") {
        symlinkSync(targetDir, dir, "dir");
      } else {
        mkdirSync(dir, { recursive: true, mode: 0o700 });
        symlinkSync(targetPath, path);
      }

      expect(loadOrPersistUserCacheSecret(() => "must-not-be-used")).toBeNull();
      expect(readFileSync(targetPath, "utf8")).toBe("target-secret");
      expect(statSync(targetPath).mode & 0o777).toBe(0o644);
      if (symlinkKind === "directory") {
        expect(statSync(targetDir).mode & 0o777).not.toBe(0o700);
      }
    },
  );

  it("rejects a non-regular destination", () => {
    const home = stubTempHome();
    const dir = join(home, USER_CACHE_SECRET_DIR_NAME);
    mkdirSync(dir, { recursive: true });
    mkdirSync(secretFilePath(home));

    expect(loadOrPersistUserCacheSecret(() => "must-not-be-used")).toBeNull();
    expect(statSync(secretFilePath(home)).isDirectory()).toBe(true);
  });

  it("preserves missing-path persistence semantics on Windows", async () => {
    const home = stubTempHome();
    vi.spyOn(process, "platform", "get").mockReturnValue("win32");
    vi.resetModules();

    const { loadOrPersistUserCacheSecret: loadWindowsSecret } =
      await import("../src/user-cache-secret-store");
    expect(loadWindowsSecret(() => "windows-secret")).toBe("windows-secret");
    expect(readFileSync(secretFilePath(home), "utf8")).toBe("windows-secret");
  });

  it("falls back to a stable in-memory secret without a home directory, warning once", async () => {
    stubHome("");
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    // The ephemeral secret and its one-time warning are module-level state,
    // and other tests in this file (the unwritable-home one) may legitimately
    // reach the fallback first. Import a fresh module instance so this test
    // observes the warn-once behavior from a cold start, whatever the order.
    vi.resetModules();
    const { resolveUserCacheSecret: freshResolve } = await import("../src/user-cache-secret");

    const first = await freshResolve();
    expect(first, "no home directory must still yield a process-lifetime secret").toMatch(/^[0-9a-f]{64}$/);
    await expect(
      freshResolve(),
      "the in-memory fallback must be stable within the process",
    ).resolves.toBe(first);

    const fallbackWarnings = warnSpy.mock.calls.filter(([msg]) =>
      String(msg).includes("TINFOIL_USER_CACHE_SECRET"),
    );
    expect(fallbackWarnings, "the ephemeral fallback must warn exactly once per process").toHaveLength(1);
  });

  it("falls back when the home path is not a directory", async () => {
    const notADir = join(mkdtempSync(join(tmpdir(), "tinfoil-ucs-")), "not-a-dir");
    writeFileSync(notADir, "x");
    stubHome(notADir);

    await expect(resolveUserCacheSecret()).resolves.not.toBe("");
  });
});

describe("withUserCacheSecret", () => {
  const eligiblePaths = [
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/responses",
    "/api/v1/chat/completions", // proxy base URL with a path prefix
    "/chat/completions", // custom base URL without a /v1 root
  ];

  for (const path of eligiblePaths) {
    it(`injects on ${path}`, async () => {
      const { calls, fetch: inner } = captureFetch();
      const secureFetch = withUserCacheSecret(inner, BASE_URL, "s1");

      const raw = '{"model":"m"}';
      const response = await secureFetch(
        `https://enclave.example.com${path}`,
        postJSON(raw, { "Content-Length": String(raw.length) }),
      );
      expect(response.status).toBe(200);

      const sent = calls[0].init!;
      const body = JSON.parse(sent.body as string);
      expect(body[USER_CACHE_SECRET_FIELD]).toBe("s1");
      expect(body.model).toBe("m");

      // Length metadata must describe the injected bytes, and re-sending the
      // request (retry machinery re-runs the wrapper) must produce the same
      // injected body.
      const injectedLength = new TextEncoder().encode(sent.body as string).byteLength;
      expect(new Headers(sent.headers).get("content-length")).toBe(String(injectedLength));
      await secureFetch(`https://enclave.example.com${path}`, postJSON(raw));
      expect(calls[1].init!.body).toBe(sent.body);
    });
  }

  it.each([
    "/v1/embeddings",
    "/embeddings",
  ])("skips non-allowlisted endpoints, forwarding the body byte-identical: %s", async (path) => {
    const { calls, fetch: inner } = captureFetch();
    const secureFetch = withUserCacheSecret(inner, BASE_URL, "s1");

    const raw = '{"model":"m","input":"text"}';
    await secureFetch(`https://enclave.example.com${path}`, postJSON(raw));
    expect(calls[0].init!.body).toBe(raw);
  });

  it("forwards a GET with no body as-is", async () => {
    const { calls, fetch: inner } = captureFetch();
    const secureFetch = withUserCacheSecret(inner, BASE_URL, "s1");

    const init: RequestInit = { method: "GET" };
    const response = await secureFetch("https://enclave.example.com/v1/models", init);
    expect(response.status).toBe(200);
    expect(calls[0].init).toBe(init);
  });

  it("does not inject when secret resolution is unavailable", async () => {
    const { calls, fetch: inner } = captureFetch();
    const secureFetch = withUserCacheSecret(inner, BASE_URL, "");
    expect(secureFetch).toBe(inner);

    const raw = '{"model":"m"}';
    await secureFetch("https://enclave.example.com/v1/chat/completions", postJSON(raw));
    expect(calls[0].init!.body).toBe(raw);
  });

  it.each([
    ["explicit per-request secret", '{"model":"m","user_cache_secret":"end-user-7"}'],
    ["explicit null", '{"model":"m","user_cache_secret":null}'],
  ])("never clobbers a non-empty or non-string field: %s", async (_name, raw) => {
    const { calls, fetch: inner } = captureFetch();
    const secureFetch = withUserCacheSecret(inner, BASE_URL, "client-level");

    await secureFetch("https://enclave.example.com/v1/chat/completions", postJSON(raw));
    expect(
      calls[0].init!.body,
      "a body that already carries the field must pass through byte-identical",
    ).toBe(raw);
  });

  it.each([
    [
      "ordinary key",
      '{"large":9007199254740993,"user_cache_secret":"","nested":{"value":1}}  ',
      '{"large":9007199254740993,"user_cache_secret":"client-level","nested":{"value":1}}  ',
    ],
    [
      "escaped key",
      '{"user_cache_secre\\u0074":""}',
      '{"user_cache_secre\\u0074":"client-level"}',
    ],
  ])("replaces an empty per-request field: %s", async (_name, raw, expected) => {
    const { calls, fetch: inner } = captureFetch();
    const secureFetch = withUserCacheSecret(inner, BASE_URL, "client-level");

    await secureFetch("https://enclave.example.com/v1/chat/completions", postJSON(raw));
    expect(calls[0].init!.body).toBe(expected);
  });

  it.each([
    "not json",
    "[1,2,3]",
    "null",
    '{"model":"m"} trailing',
    '{"model":"m"}}',
    '{"model":"m"}]',
    '{"model":"m"}} garbage',
  ])("forwards a non-object body untouched: %s", async (raw) => {
    // The trailing '}' / ']' cases matter: a lenient parser would re-serialize
    // the leading object and silently drop the trailing bytes, turning a body
    // the server rejects into one it accepts.
    const { calls, fetch: inner } = captureFetch();
    const secureFetch = withUserCacheSecret(inner, BASE_URL, "s1");

    await secureFetch("https://enclave.example.com/v1/chat/completions", postJSON(raw));
    expect(calls[0].init!.body).toBe(raw);
  });

  it.each([
    ["ArrayBuffer", new TextEncoder().encode('{"model":"m"}').buffer],
    ["typed array", new TextEncoder().encode('{"model":"m"}')],
    ["DataView", new DataView(new TextEncoder().encode('{"model":"m"}').buffer)],
  ])("injects into an ordinary UTF-8 %s body", async (_name, requestBody) => {
    const { calls, fetch: inner } = captureFetch();
    const secureFetch = withUserCacheSecret(inner, BASE_URL, "s1");

    await secureFetch("https://enclave.example.com/v1/chat/completions", {
      method: "POST",
      body: requestBody,
    });

    const body = JSON.parse(calls[0].init!.body as string);
    expect(body[USER_CACHE_SECRET_FIELD]).toBe("s1");
    expect(body.model).toBe("m");
  });

  it("forwards an unsupported stream body unchanged", async () => {
    const { calls, fetch: inner } = captureFetch();
    const secureFetch = withUserCacheSecret(inner, BASE_URL, "s1");
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{"model":"m"}'));
        controller.close();
      },
    });

    await secureFetch("https://enclave.example.com/v1/chat/completions", {
      method: "POST",
      body: stream,
      duplex: "half",
    } as RequestInit);

    expect(calls[0].init!.body).toBe(stream);
  });

  it("forwards a Request body unchanged", async () => {
    const { calls, fetch: inner } = captureFetch();
    const secureFetch = withUserCacheSecret(inner, BASE_URL, "s1");
    const request = new Request(
      "https://enclave.example.com/v1/chat/completions",
      postJSON('{"model":"m"}'),
    );

    await secureFetch(request);

    expect(calls[0].input).toBe(request);
    expect(calls[0].init).toBeUndefined();
    expect(request.bodyUsed).toBe(false);
  });

  it("preserves Request headers when an init body overrides the Request body", async () => {
    const { calls, fetch: inner } = captureFetch();
    const secureFetch = withUserCacheSecret(inner, BASE_URL, "s1");
    const request = new Request(
      "https://enclave.example.com/v1/chat/completions",
      postJSON('{"model":"request"}', {
        "Content-Length": "1",
        "X-Source": "request",
      }),
    );

    await secureFetch(request, { body: '{"model":"override"}' });

    const sent = calls[0].init!;
    const body = JSON.parse(sent.body as string);
    const headers = new Headers(sent.headers);
    expect(body.model).toBe("override");
    expect(body[USER_CACHE_SECRET_FIELD]).toBe("s1");
    expect(headers.get("content-type")).toBe("application/json");
    expect(headers.get("x-source")).toBe("request");
    expect(headers.get("content-length")).toBe(
      String(new TextEncoder().encode(sent.body as string).byteLength),
    );
  });

  it("prefers init headers when an init body overrides a Request body", async () => {
    const { calls, fetch: inner } = captureFetch();
    const secureFetch = withUserCacheSecret(inner, BASE_URL, "s1");
    const request = new Request(
      "https://enclave.example.com/v1/chat/completions",
      postJSON('{"model":"request"}', { "X-Source": "request" }),
    );

    await secureFetch(request, {
      body: '{"model":"override"}',
      headers: {
        "Content-Type": "application/json",
        "X-Source": "init",
      },
    });

    const sent = calls[0].init!;
    const body = JSON.parse(sent.body as string);
    expect(body[USER_CACHE_SECRET_FIELD]).toBe("s1");
    expect(new Headers(sent.headers).get("x-source")).toBe("init");
  });

  it("forwards an invalid UTF-8 typed-array body byte-identical", async () => {
    const bytes = new Uint8Array([0x7b, 0x22, 0x6e, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d]);
    const { calls, fetch: inner } = captureFetch();
    const secureFetch = withUserCacheSecret(inner, BASE_URL, "s1");

    await secureFetch("https://enclave.example.com/v1/chat/completions", {
      method: "POST",
      body: bytes,
    });
    expect(calls[0].init!.body).toBe(bytes);
  });

  it("still injects with trailing whitespace after the object", async () => {
    // Trailing whitespace is not trailing data: strict JSON parsers accept
    // it, so the injection must too — clients routinely end bodies with \n.
    const { calls, fetch: inner } = captureFetch();
    const secureFetch = withUserCacheSecret(inner, BASE_URL, "s1");

    await secureFetch("https://enclave.example.com/v1/chat/completions", postJSON('{"model":"m"}\n\t '));
    const body = JSON.parse(calls[0].init!.body as string);
    expect(body[USER_CACHE_SECRET_FIELD]).toBe("s1");
    expect(body.model).toBe("m");
  });

  it("preserves number precision across injection", async () => {
    // 2^53+1 is not representable as a float64; re-serializing the parsed
    // object (instead of splicing the original text) would corrupt it.
    const { calls, fetch: inner } = captureFetch();
    const secureFetch = withUserCacheSecret(inner, BASE_URL, "s1");

    await secureFetch(
      "https://enclave.example.com/v1/chat/completions",
      postJSON('{"model":"m","seed":9007199254740993}'),
    );
    const sent = calls[0].init!.body as string;
    expect(sent).toContain('"seed":9007199254740993');
    expect(JSON.parse(sent)[USER_CACHE_SECRET_FIELD]).toBe("s1");
  });

  it("injects into an empty JSON object without a stray comma", () => {
    expect(injectUserCacheSecret("{}", "s1")).toBe('{"user_cache_secret":"s1"}');
  });
});

describe("createEncryptedBodyFetch user cache secret", () => {
  it("injects before the EHBP transport seals the body", async () => {
    // Capture the plaintext handed to the sealing transport: the field must
    // be present there, so it is encrypted with the rest of the body.
    const requestSpy = vi
      .spyOn(Transport.prototype, "request")
      .mockImplementation(async () => new Response("ok", { status: 200 }));

    const identity = await Identity.generate();
    const transport = createEncryptedBodyFetch(
      "https://enclave.example.com",
      await identity.getPublicKeyHex(),
      undefined,
      "s1",
    );

    await transport.fetch("/v1/chat/completions", postJSON('{"model":"m"}'));

    const [url, init] = requestSpy.mock.calls[0];
    expect(url).toBe("https://enclave.example.com/v1/chat/completions");
    expect(JSON.parse(init!.body as string)[USER_CACHE_SECRET_FIELD]).toBe("s1");
  });

  it("leaves a caller-set field untouched inside the sealing boundary", async () => {
    const requestSpy = vi
      .spyOn(Transport.prototype, "request")
      .mockImplementation(async () => new Response("ok", { status: 200 }));

    const identity = await Identity.generate();
    const transport = createEncryptedBodyFetch(
      "https://enclave.example.com",
      await identity.getPublicKeyHex(),
      undefined,
      "client-level",
    );

    const raw = '{"model":"m","user_cache_secret":"end-user-7"}';
    await transport.fetch("/v1/chat/completions", postJSON(raw));

    expect(requestSpy.mock.calls[0][1]!.body).toBe(raw);
  });
});

describe("user cache secret through the OpenAI client", () => {
  let server: Server;
  let baseURL: string;
  const received: Array<{ path: string; body: Record<string, unknown> }> = [];

  beforeEach(async () => {
    received.length = 0;
    server = createServer((req, res) => {
      let data = "";
      req.on("data", (chunk) => (data += chunk));
      req.on("end", () => {
        received.push({ path: req.url!, body: JSON.parse(data) });
        res.setHeader("Content-Type", "application/json");
        res.end(
          JSON.stringify({
            id: "c1",
            object: "chat.completion",
            created: 0,
            model: "m",
            choices: [
              { index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" },
            ],
          }),
        );
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    baseURL = `http://127.0.0.1:${(server.address() as AddressInfo).port}/v1`;
  });

  afterEach(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  it("the client-level secret rides real requests; a per-request field wins", async () => {
    // Drive the real OpenAI client through the injection wrapper, pinning
    // that the secret rides requests exactly as the SDK builds them.
    const oai = new OpenAI({
      apiKey: "test",
      baseURL,
      fetch: withUserCacheSecret(fetch, baseURL, "client-level"),
    });

    const params: OpenAI.ChatCompletionCreateParams = {
      messages: [{ role: "user", content: "hi" }],
      model: "m",
    };

    await oai.chat.completions.create(params);
    expect(received[0].path).toBe("/v1/chat/completions");
    expect(received[0].body[USER_CACHE_SECRET_FIELD]).toBe("client-level");
    expect(received[0].body.model).toBe("m");

    // A per-request field set through the public API must win over the
    // client-level secret.
    await oai.chat.completions.create({
      ...params,
      [USER_CACHE_SECRET_FIELD]: "end-user-7",
    } as OpenAI.ChatCompletionCreateParams);
    expect(received[1].body[USER_CACHE_SECRET_FIELD]).toBe("end-user-7");
  });
});
