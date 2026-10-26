import { beforeEach, describe, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({ fetch: vi.fn(), ready: vi.fn(async () => {}), inspect: vi.fn(() => undefined) }));
vi.mock("../src/client.js", () => ({ Client: class { fetch = mocks.fetch; ready = mocks.ready; inspect = mocks.inspect; getBaseURL() { return "https://enclave.test/v1/"; } }, copyVerificationOptions: (value: unknown) => value }));
import { TinfoilAI } from "../src/tinfoil-ai.js";
import { ConfigurationError } from "../src/errors.js";
beforeEach(() => { mocks.fetch.mockReset(); mocks.ready.mockClear(); mocks.inspect.mockClear(); });
describe("native OpenAI facade", () => {
  it("preserves resources, APIPromise response access and schema bytes through the secure hook", async () => {
    mocks.fetch.mockResolvedValue(Response.json({ id: "c", choices: [{ message: { role: "assistant", content: "ok" }, finish_reason: "stop" }] }, { headers: { "x-request-id": "r" } }));
    const client = new TinfoilAI({ apiKey: "key", maxRetries: 0 });
    const schema = { type: "object", properties: { id: { type: "string", enum: ["a", "b"], description: "exact ID" } }, required: ["id"], additionalProperties: false };
    const pending = client.chat.completions.create({ model: "m", messages: [{ role: "user", content: "hello" }], response_format: { type: "json_schema", json_schema: { name: "selection", description: "selection metadata", strict: true, schema } } });
    expect(typeof pending.withResponse).toBe("function"); const { response, data } = await pending.withResponse();
    expect(response.headers.get("x-request-id")).toBe("r"); expect(data.id).toBe("c");
    const [, init] = mocks.fetch.mock.calls[0]; const body = JSON.parse(init.body);
    expect(body.response_format.json_schema).toEqual({ name: "selection", description: "selection metadata", strict: true, schema });
    expect(new Headers(init.headers).get("authorization")).toBe("Bearer key");
    expect(client.decisions).toBeDefined(); expect(client.batches).toBeDefined(); expect(client.uploads).toBeDefined(); expect(client.vectorStores).toBeDefined();
  });
  it("sends Decisions and ordinary schema-free JSON unchanged", async () => {
    mocks.fetch.mockResolvedValue(Response.json({ id: "decision", output: [] }));
    const client = new TinfoilAI({ apiKey: "key", maxRetries: 0 });
    await client.decisions.create({ model: "m", input: "pick", response_format: { type: "json_object" } } as never);
    expect(String(mocks.fetch.mock.calls[0][0])).toContain("/decisions");
    expect(JSON.parse(mocks.fetch.mock.calls[0][1].body).response_format).toEqual({ type: "json_object" });
  });
  it("forwards provider API errors with SDK retries disabled", async () => {
    mocks.fetch.mockResolvedValue(Response.json({ error: { message: "schema unsupported", type: "invalid_request_error" } }, { status: 400 }));
    const client = new TinfoilAI({ apiKey: "key", maxRetries: 0 });
    await expect(client.chat.completions.create({ model: "m", messages: [] })).rejects.toMatchObject({ status: 400 });
    expect(mocks.fetch).toHaveBeenCalledTimes(1);
  });
  it("keeps inspection passive and resolves only SDK credentials", () => {
    const client = new TinfoilAI({ apiKey: "key" }); expect(client.inspect()).toBeUndefined(); expect(mocks.ready).not.toHaveBeenCalled();
    vi.stubEnv("TINFOIL_API_KEY", ""); vi.stubEnv("OPENAI_API_KEY", "unrelated");
    try { expect(() => new TinfoilAI()).toThrow(ConfigurationError); } finally { vi.unstubAllEnvs(); }
  });
  it("preserves caller-selected tools, metadata and best-effort schema strictness", async () => {
    mocks.fetch.mockResolvedValue(Response.json({ id: "tools", choices: [{ message: { role: "assistant", content: null, tool_calls: [{ id: "call", type: "function", function: { name: "choose", arguments: '{"id":"a"}' } }] }, finish_reason: "tool_calls" }] }));
    const client = new TinfoilAI({ apiKey: "key", maxRetries: 0 });
    const parameters = { type: "object", properties: { id: { type: "string", enum: ["a", "b"], description: "Exact ID" } }, required: ["id"], additionalProperties: false };
    const tools = [{ type: "function" as const, function: { name: "choose", description: "Choose a supplied ID", strict: false, parameters } }];
    const tool_choice = { type: "function" as const, function: { name: "choose" } };
    await client.chat.completions.create({ model: "m", messages: [{ role: "user", content: "choose" }], tools, tool_choice, parallel_tool_calls: false, metadata: { test_id: "native_metadata" }, response_format: { type: "json_schema", json_schema: { name: "best_effort", strict: false, schema: parameters } } });
    const body = JSON.parse(mocks.fetch.mock.calls[0][1].body);
    expect(body).toMatchObject({ tools, tool_choice, parallel_tool_calls: false, metadata: { test_id: "native_metadata" } });
    expect(body.response_format.json_schema.strict).toBe(false); expect(body.tools[0].function.parameters).toEqual(parameters);
  });

});
