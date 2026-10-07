import { beforeEach, describe, expect, it, vi } from "vitest";
import { generateText, NoObjectGeneratedError, Output, streamText } from "ai";
import { z } from "zod";
import { createTinfoilAI } from "../src/ai-sdk-provider";

const transport = vi.hoisted(() => ({ fetch: vi.fn<typeof fetch>() }));

vi.mock("../src/secure-client", () => ({
  SecureClient: class {
    async ready() {}
    getBaseURL() { return "https://enclave.invalid/v1/"; }
    fetch = transport.fetch;
  },
}));

const MODEL = "gpt-oss-120b";
const PERSON_IDS = ["person_alex", "person_sam"] as const;
const EVIDENCE_IDS = ["evidence_intro", "evidence_correction"] as const;
const PERSON_DESCRIPTION = "Exact person ID from the supplied records, not a name or explanation.";
const OUTPUT_NAME = "evidence_selection";
const OUTPUT_DESCRIPTION = "Select a person and the supporting evidence IDs.";
const PROMPT = "Return the person ID and evidence IDs for the supplied synthetic records.";
const selectionSchema = z.object({
  person_id: z.enum(PERSON_IDS).describe(PERSON_DESCRIPTION),
  evidence_ids: z.array(z.enum(EVIDENCE_IDS)).min(1),
});
const selection = { person_id: PERSON_IDS[0], evidence_ids: [EVIDENCE_IDS[0]] };

function structuredOutput() {
  return Output.object({
    name: OUTPUT_NAME,
    description: OUTPUT_DESCRIPTION,
    schema: selectionSchema,
  });
}

function completion(content: string) {
  return Response.json({
    choices: [{ message: { role: "assistant", content }, finish_reason: "stop" }],
  });
}

function sentBody() {
  expect(transport.fetch).toHaveBeenCalledTimes(1);
  const [url, init] = transport.fetch.mock.calls[0];
  expect(url).toBe("https://enclave.invalid/v1/chat/completions");
  return JSON.parse(init!.body as string);
}

function expectSelectionSchema(body: ReturnType<typeof sentBody>) {
  expect(body.model).toBe(MODEL);
  expect(body.response_format).toEqual({
    type: "json_schema",
    json_schema: {
      name: OUTPUT_NAME,
      description: OUTPUT_DESCRIPTION,
      strict: true,
      schema: expect.objectContaining({
        type: "object",
        properties: {
          person_id: {
            type: "string",
            enum: [...PERSON_IDS],
            description: PERSON_DESCRIPTION,
          },
          evidence_ids: {
            type: "array",
            items: { type: "string", enum: [...EVIDENCE_IDS] },
            minItems: 1,
          },
        },
        required: ["person_id", "evidence_ids"],
        additionalProperties: false,
      }),
    },
  });
}

describe("createTinfoilAI structured output requests", () => {
  beforeEach(() => transport.fetch.mockReset());

  it("sends exact-ID schemas through the real provider instead of downgrading to JSON mode", async () => {
    transport.fetch.mockResolvedValueOnce(completion(JSON.stringify(selection)));
    const provider = await createTinfoilAI("test-key");

    const result = await generateText({
      model: provider(MODEL),
      output: structuredOutput(),
      prompt: PROMPT,
      maxRetries: 0,
    });

    expectSelectionSchema(sentBody());
    expect(result.output).toEqual(selection);
    expect(result.warnings).toEqual([]);
  });

  it("preserves the schema when streaming and validates the final output", async () => {
    const chunks = [
      { choices: [{ delta: { content: JSON.stringify(selection) }, finish_reason: null }] },
      { choices: [{ delta: {}, finish_reason: "stop" }] },
    ];
    transport.fetch.mockResolvedValueOnce(new Response(
      chunks.map(chunk => `data: ${JSON.stringify(chunk)}\n\n`).join("") + "data: [DONE]\n\n",
      { headers: { "Content-Type": "text/event-stream" } },
    ));
    const provider = await createTinfoilAI("test-key");

    const result = streamText({
      model: provider(MODEL),
      output: structuredOutput(),
      prompt: PROMPT,
      maxRetries: 0,
    });
    await result.consumeStream();

    expect(await result.output).toEqual(selection);
    const body = sentBody();
    expectSelectionSchema(body);
    expect(body.stream).toBe(true);
    expect(await result.warnings).toEqual([]);
  });

  it.each([
    { ...selection, person_id: "Alex, the person who made the introduction" },
    { ...selection, evidence_ids: [PERSON_IDS[0]] },
    { ...selection, evidence_ids: [] },
  ])("rejects contract-invalid content: %j", async invalidSelection => {
    transport.fetch.mockResolvedValueOnce(completion(JSON.stringify(invalidSelection)));
    const provider = await createTinfoilAI("test-key");

    await expect(generateText({
      model: provider(MODEL),
      output: structuredOutput(),
      prompt: PROMPT,
      maxRetries: 0,
    })).rejects.toBeInstanceOf(NoObjectGeneratedError);
    expectSelectionSchema(sentBody());
  });

  it("leaves plain text generation unconstrained", async () => {
    const text = "A synthetic response.";
    transport.fetch.mockResolvedValueOnce(completion(text));
    const provider = await createTinfoilAI("test-key");

    const result = await generateText({
      model: provider(MODEL),
      prompt: PROMPT,
      maxRetries: 0,
    });

    expect(result.text).toBe(text);
    expect(sentBody()).not.toHaveProperty("response_format");
  });

  it("keeps schema-free JSON requests in JSON mode", async () => {
    transport.fetch.mockResolvedValueOnce(completion(JSON.stringify(selection)));
    const provider = await createTinfoilAI("test-key");

    const result = await generateText({
      model: provider(MODEL),
      output: Output.json(),
      prompt: PROMPT,
      maxRetries: 0,
    });

    expect(result.output).toEqual(selection);
    expect(sentBody().response_format).toEqual({ type: "json_object" });
  });
});
