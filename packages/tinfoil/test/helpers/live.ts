/**
 * The live service the integration lanes run against, and the requests they
 * make through an OpenAI client. The checks throw plain errors rather than
 * using a test runner's assertions, so the same helpers serve the Node,
 * browser and Bun lanes. The live model reasons before it answers, so a
 * finished reply may carry its text in a reasoning field with empty content;
 * the checks are on the completion's shape and its terminal finish reason,
 * and on the text only when the model finished its answer.
 */
import type OpenAI from "openai";

export const LIVE_HOST = "inference.tinfoil.sh";
export const LIVE_REPO = "tinfoilsh/confidential-model-router";
/** The router's name is Tinfoil's in both namespaces. */
export const LIVE_PIN = { repo: LIVE_REPO, project: LIVE_REPO };
export const LIVE_MODEL = "gpt-oss-120b";
/** The finish reasons a completed request ends with: the answer finished, or the token budget ran out. */
export const TERMINAL_FINISH_REASONS: readonly string[] = ["stop", "length"];
/** The lowercase hex of a SHA-256 fingerprint, the form an attested TLS key takes. */
export const SHA256_HEX = /^[0-9a-f]{64}$/;

interface ReplyMessage {
  readonly role?: string;
  readonly content?: string | null;
  readonly reasoning?: string | null;
  readonly reasoning_content?: string | null;
}

function check(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

/** Completes one chat through `ai` and returns the reply's finish reason and text, checking the reply's shape. */
export async function completeChat(ai: OpenAI, model = LIVE_MODEL): Promise<{ finishReason: string; text: string }> {
  const reply = await ai.chat.completions.create({ model, messages: [{ role: "user", content: "Say the single word: pong" }], max_tokens: 512 });
  check(reply.choices.length > 0, "completion has no choices");
  const choice = reply.choices[0]!;
  const message = choice.message as ReplyMessage;
  check(message.role === "assistant", `completion role is ${JSON.stringify(message.role)}, want "assistant"`);
  check(TERMINAL_FINISH_REASONS.includes(choice.finish_reason), `completion finish_reason is ${JSON.stringify(choice.finish_reason)}, want one of ${TERMINAL_FINISH_REASONS.join(", ")}`);
  const text = message.content || message.reasoning || message.reasoning_content || "";
  if (choice.finish_reason === "stop") check(text !== "", "completion finished with no content and no reasoning");
  return { finishReason: choice.finish_reason, text };
}

/**
 * Streams one chat through `ai` and returns how many chunks carried text and
 * the finish reason, checking that more than one chunk arrived before the
 * final one and that the final one is terminal.
 */
export async function streamChat(ai: OpenAI, model = LIVE_MODEL): Promise<{ deltas: number; finishReason: string }> {
  const stream = await ai.chat.completions.create({ model, messages: [{ role: "user", content: "Count from 1 to 20, separated by spaces." }], stream: true, max_tokens: 512 });
  let deltas = 0;
  let finishReason: string | undefined;
  for await (const chunk of stream) {
    check(finishReason === undefined, "a chunk arrived after the finish reason");
    const delta = chunk.choices[0]?.delta as ReplyMessage | undefined;
    if (delta?.content || delta?.reasoning || delta?.reasoning_content) deltas++;
    const reason = chunk.choices[0]?.finish_reason;
    if (reason) finishReason = reason;
  }
  check(deltas > 1, `stream carried ${deltas} chunks with text, want more than one`);
  check(finishReason !== undefined && TERMINAL_FINISH_REASONS.includes(finishReason), `stream finish_reason is ${JSON.stringify(finishReason)}, want one of ${TERMINAL_FINISH_REASONS.join(", ")}`);
  return { deltas, finishReason: finishReason! };
}
