/**
 * Streaming Chat Completion Example
 *
 * Stream responses token-by-token using server-sent events (SSE).
 * Useful for chat UIs where you want to display responses as they're generated.
 *
 * Prerequisites:
 * - Export your API key: export TINFOIL_API_KEY="<YOUR_API_KEY>"
 *
 * Run from packages/tinfoil: npx ts-node examples/streaming/main.ts
 */
import { createClient } from "tinfoil";

async function main() {
  try {
    const client = await createClient({
      apiKey: process.env.TINFOIL_API_KEY,
    });

    console.log("Streaming response:\n");

    const stream = await client.chat.completions.create({
      messages: [
        { role: "user", content: "Write a short poem about secure computing." },
      ],
      model: "gpt-oss-120b",
      stream: true,
    });

    // Process chunks as they arrive
    for await (const chunk of stream) {
      const content = chunk.choices[0]?.delta?.content;
      if (content) {
        process.stdout.write(content);
      }
    }

    console.log("\n\nStream complete.");
  } catch (error) {
    console.error("Error:", error);
    process.exit(1);
  }
}

main();
