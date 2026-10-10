import { describe, it, expect, vi } from "vitest";
import { createHash } from "node:crypto";
import { Identity, Transport } from "ehbp";
import { CACHE_PREFIX_HEADER, MODEL_HEADER, withRoutingHeaders } from "../src/user-cache-secret";
import { createEncryptedBodyFetch } from "../src/encrypted-body-fetch";

const CHAT = "/v1/chat/completions";
const RESPONSES = "/v1/responses";
const USER = { role: "user", content: "hi" };
const SYSTEM = { role: "system", content: "you are helpful" };

const post = (body: unknown, headers: Record<string, string> = {}): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json", ...headers },
  body: typeof body === "string" ? body : JSON.stringify(body),
});

/** The headers a request would arrive at the gateway with. */
async function routed(body: unknown, path = CHAT, secret = "s1", headers = {}): Promise<Headers> {
  return new Headers((await withRoutingHeaders(post(body, headers), path, secret))!.headers);
}

/** Recomputes the wire format independently of the implementation. */
const prefixOf = (secret: string, head: unknown) =>
  createHash("sha256").update(`${secret}\u0000${JSON.stringify(head)}`).digest("hex");

describe("withRoutingHeaders", () => {
  // name, path, body, expected cache prefix (null: routed on the model alone)
  const cases: [string, string, object, string | null][] = [
    ["chat hashes the first message", CHAT, { model: "m", messages: [SYSTEM, USER] }, prefixOf("s1", SYSTEM)],
    ["responses prefer the standing instructions", RESPONSES, { model: "m", instructions: "be brief", input: [USER] }, prefixOf("s1", "be brief")],
    ["responses without instructions hash the first input", RESPONSES, { model: "m", input: [USER] }, prefixOf("s1", USER)],
    ["completions hash the prompt", "/v1/completions", { model: "m", prompt: "once upon a time" }, prefixOf("s1", "once upon a time")],
    ["endpoints that do not prefix-cache are routed on the model alone", "/v1/embeddings", { model: "m", input: "hi" }, null],
    ["a body with no prompt is routed on the model alone", CHAT, { model: "m", messages: [] }, null],
  ];
  it.each(cases)("%s", async (_name, path, body, prefix) => {
    const headers = await routed(body, path);
    expect(headers.get(MODEL_HEADER)).toBe("m");
    expect(headers.get(CACHE_PREFIX_HEADER)).toBe(prefix);
  });

  it("keys the prefix on the conversation and the secret, and nothing else", async () => {
    const chat = (head: unknown, rest: unknown[] = []) => ({ model: "m", messages: [head, ...rest] });
    const mine = (await routed(chat(USER))).get(CACHE_PREFIX_HEADER);

    // The whole point: turn 2 must hash the same as turn 1, or the gateway
    // sends it to a replica with a cold cache.
    const turn2 = await routed(chat(USER, [{ role: "assistant", content: "hello" }, SYSTEM]));
    expect(turn2.get(CACHE_PREFIX_HEADER)).toBe(mine);

    expect((await routed(chat(SYSTEM))).get(CACHE_PREFIX_HEADER)).not.toBe(mine);
    expect((await routed(chat(USER), CHAT, "s2")).get(CACHE_PREFIX_HEADER)).not.toBe(mine);
    expect((await routed(chat(USER), CHAT, "")).has(CACHE_PREFIX_HEADER)).toBe(false);
    // A different model shares the prefix: the gateway picks the pool by
    // model first, so the same client's prompt head lands consistently in each.
    const otherModel = await routed({ model: "other", messages: [USER] });
    expect(otherModel.get(CACHE_PREFIX_HEADER)).toBe(mine);
  });

  it("leaves the body, the caller's headers, and the caller's pins alone", async () => {
    const raw = JSON.stringify({ model: "m", seed: 1, messages: [USER] });
    const pins = { [MODEL_HEADER]: "pinned", [CACHE_PREFIX_HEADER]: "pinned-prefix" };
    const init = (await withRoutingHeaders(post(raw, { ...pins, "X-Source": "caller" }), CHAT, "s1"))!;

    expect(init.body).toBe(raw);
    const headers = new Headers(init.headers);
    expect(headers.get("x-source")).toBe("caller");
    expect(headers.get(MODEL_HEADER)).toBe("pinned");
    expect(headers.get(CACHE_PREFIX_HEADER)).toBe("pinned-prefix");
  });

  it("preserves a request it cannot read", async () => {
    const unreadable: (RequestInit | undefined)[] = [
      { method: "GET" },
      post("not json"),
      post("[1,2,3]"),
      { method: "POST", body: new ReadableStream() as unknown as BodyInit },
      post({ messages: [USER] }), // no model
    ];
    for (const init of unreadable) {
      const routedInit = await withRoutingHeaders(init, CHAT, "s1");
      expect(new Headers(routedInit!.headers).has(MODEL_HEADER)).toBe(false);
    }
    expect(await withRoutingHeaders(undefined, CHAT, "s1")).toBeUndefined();
  });
});

describe("createEncryptedBodyFetch routing headers", () => {
  it("hands the gateway's headers to the transport in the clear", async () => {
    const request = vi
      .spyOn(Transport.prototype, "request")
      .mockResolvedValue(new Response("ok", { status: 200 }));
    const transport = createEncryptedBodyFetch(
      "https://gateway.example.com",
      await (await Identity.generate()).getPublicKeyHex(),
      undefined,
      "s1",
    );

    await transport.fetch(CHAT, post({ model: "m", messages: [USER] }));

    const init = request.mock.calls[0][1]!;
    const headers = new Headers(init.headers);
    expect(headers.get(MODEL_HEADER)).toBe("m");
    expect(headers.get(CACHE_PREFIX_HEADER)).toBe(prefixOf("s1", USER));
    // The secret itself stays in the body the transport seals, never in a header.
    expect(init.body as string).toContain("s1");
    expect([...headers.values()].some((value) => value.includes("s1"))).toBe(false);
    vi.restoreAllMocks();
  });
});
